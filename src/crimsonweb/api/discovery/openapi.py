"""Offline OpenAPI 3.0/3.1 and Swagger 2 structure; no reference/server fetching."""

import json
import re

from .urls import fingerprint, masked_path, metadata_route, parameter


class DiscoveryInputError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class OpenAPIImporter:
    def __init__(self, maximum=500):
        self.maximum = maximum
        self.limitations = {
            "openapi_declared_not_verified",
            "external_references_not_fetched",
            "openapi_examples_descriptions_discarded",
        }

    def resolve(self, document, value, depth=0):
        if not isinstance(value, dict):
            return {}
        ref = value.get("$ref")
        if ref is None:
            return value
        if not isinstance(ref, str) or not ref.startswith("#/") or len(ref) > 256:
            self.limitations.add("external_or_invalid_ref_ignored")
            return {}
        if depth >= 4:
            self.limitations.add("local_ref_depth_limit")
            return {}
        current = document
        for token in ref[2:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, dict) or token not in current:
                self.limitations.add("unresolved_local_ref")
                return {}
            current = current[token]
        return self.resolve(document, current, depth + 1)

    def parse(self, document, base_url=None):
        if (
            not isinstance(document, dict)
            or not (
                document.get("swagger") == "2.0"
                or re.fullmatch(r"3\.(?:0|1)\.\d+", str(document.get("openapi", "")))
            )
            or not isinstance(document.get("paths"), dict)
        ):
            raise DiscoveryInputError("unsupported_openapi_document")
        # Byte cap also applies to direct Python callers, not just HTTP upload.
        try:
            encoded = json.dumps(document, ensure_ascii=False, allow_nan=False).encode()
        except (TypeError, ValueError, RecursionError) as exc:
            raise DiscoveryInputError("invalid_openapi_document") from exc
        if len(encoded) > 1048576:
            raise DiscoveryInputError("openapi_document_too_large")
        origin_ref = metadata_route(base_url)[0] if base_url else "offline"
        schemes = (
            document.get("components", {}).get("securitySchemes", {})
            if isinstance(document.get("components"), dict)
            else {}
        )
        if document.get("swagger") == "2.0":
            schemes = document.get("securityDefinitions", {})
        if not isinstance(schemes, dict):
            schemes = {}
        results = []
        for path, original in document["paths"].items():
            if (
                not isinstance(path, str)
                or not path.startswith("/")
                or len(path) > 2048
                or any(c in path for c in "%?#\\")
                or "//" in path
                or any(p in {".", ".."} for p in path.split("/"))
            ):
                self.limitations.add("openapi_path_rejected")
                continue
            entry = self.resolve(document, original)
            for method in ("get", "head", "post", "put", "patch", "delete", "options"):
                operation = entry.get(method)
                if not isinstance(operation, dict):
                    continue
                if len(results) >= self.maximum:
                    self.limitations.add("endpoint_limit")
                    return results
                params = []
                declared = []
                for source in (
                    entry.get("parameters", []),
                    operation.get("parameters", []),
                ):
                    if isinstance(source, list):
                        declared.extend(source[:50])
                for item in declared:
                    item = self.resolve(document, item)
                    location = item.get("in")
                    if location == "formData":
                        location = "form"
                    if not isinstance(location, str) or location not in {
                        "query",
                        "path",
                        "body",
                        "header",
                        "form",
                    }:
                        continue
                    schema = self.resolve(document, item.get("schema", item))
                    result = parameter(item.get("name"), location, schema.get("type"))
                    if result and result not in params:
                        params.append(result)
                request_body = self.resolve(document, operation.get("requestBody", {}))
                content = request_body.get("content", {})
                if isinstance(content, dict):
                    for value in list(content.values())[:3]:
                        schema = (
                            self.resolve(document, value.get("schema", {}))
                            if isinstance(value, dict)
                            else {}
                        )
                        properties = schema.get("properties", {})
                        if isinstance(properties, dict):
                            for name, prop in list(properties.items())[:50]:
                                prop = self.resolve(document, prop)
                                result = parameter(name, "body", prop.get("type"))
                                if result and result not in params:
                                    params.append(result)
                # Include route placeholders even when parameter declarations are absent.
                for name in re.findall(r"\{([A-Za-z_][A-Za-z0-9_]{0,63})\}", path):
                    result = parameter(name, "path")
                    if result and not any(
                        p.name == result.name and p.location == "path" for p in params
                    ):
                        params.append(result)
                security = operation.get("security", document.get("security", []))
                indicators = []
                if (
                    isinstance(security, list)
                    and security
                    and all(isinstance(r, dict) and bool(r) for r in security)
                ):
                    indicators.append("openapi_security_declared")
                    for requirement in security[:10]:
                        for name in requirement:
                            definition = self.resolve(document, schemes.get(name, {}))
                            scheme_type = definition.get("type")
                            if isinstance(scheme_type, str) and scheme_type in {
                                "apiKey",
                                "http",
                                "oauth2",
                                "openIdConnect",
                                "basic",
                            }:
                                indicators.append("openapi_" + scheme_type)
                else:
                    indicators.append("openapi_no_mandatory_security_declared")
                content_types = []
                responses = operation.get("responses", {})
                if isinstance(responses, dict):
                    for value in list(responses.values())[:10]:
                        response = self.resolve(document, value)
                        response_content = response.get("content", {})
                        if isinstance(response_content, dict):
                            content_types.extend(
                                k
                                for k in response_content
                                if isinstance(k, str)
                                and len(k) <= 100
                                and re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+-]+", k)
                            )
                results.append(
                    {
                        "origin_ref": origin_ref,
                        "path": masked_path(path),
                        "method": method.upper(),
                        "parameters": params[:100],
                        "authentication_indicators": sorted(set(indicators))[:10],
                        "content_type": min(content_types) if content_types else None,
                    }
                )
        return results

    @staticmethod
    def source_digest(document):
        return fingerprint(
            json.dumps(document, sort_keys=True, ensure_ascii=False, allow_nan=False)
        )
