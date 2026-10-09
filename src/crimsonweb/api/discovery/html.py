"""Structural HTML extraction. Text, scripts, field values and credentials discarded."""

from html.parser import HTMLParser

from .models import Form
from .urls import masked_path, metadata_link, parameter


class FormAnalyzer(HTMLParser):
    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.links = []
        self.forms = []
        self.limitations = set()
        self.current = None
        self.ignored = 0

    def handle_starttag(self, tag, attributes):
        if tag in {"script", "style", "template"}:
            self.ignored += 1
            return
        if self.ignored:
            return
        attrs = dict(attributes)
        if tag in {"a", "area"} and attrs.get("href"):
            if len(self.links) < 128:
                self.links.append(attrs["href"][:2049])
            else:
                self.limitations.add("html_link_limit")
        if tag == "base":
            self.limitations.add("html_base_ignored")
        if tag == "form":
            if self.current is not None:
                self.limitations.add("nested_form_ignored")
                return
            if len(self.forms) >= 10:
                self.limitations.add("html_form_limit")
                return
            method = (attrs.get("method") or "GET").upper()
            if method not in {"GET", "POST"}:
                self.limitations.add("unsupported_html_form_method")
                return
            try:
                action = metadata_link(self.base, attrs.get("action") or self.base)
            except ValueError:
                self.limitations.add("form_action_rejected")
                return
            self.current = {
                "action": action,
                "method": method,
                "fields": [],
                "password": False,
            }
        if tag in {"input", "textarea", "select", "button"} and self.current:
            kind = (attrs.get("type") or "text").lower()
            self.current["password"] |= kind == "password"
            item = parameter(
                attrs.get("name"),
                "form",
                "number"
                if kind == "number"
                else "boolean"
                if kind in {"checkbox", "radio"}
                else "string",
            )
            if item:
                if len(self.current["fields"]) < 50:
                    if item not in self.current["fields"]:
                        self.current["fields"].append(item)
                else:
                    self.limitations.add("html_field_limit")

    def handle_endtag(self, tag):
        if tag in {"script", "style", "template"} and self.ignored:
            self.ignored -= 1
            return
        if tag == "form" and self.current and not self.ignored:
            self.forms.append(self.current)
            self.current = None

    def close(self):
        super().close()
        if self.current:
            self.forms.append(self.current)
            self.current = None

    @staticmethod
    def form_record(value):
        from urllib.parse import urlsplit

        return Form(
            action_path=masked_path(urlsplit(value["action"]).path),
            method=value["method"],
            fields=value["fields"],
            password_field_present=value["password"],
        )
