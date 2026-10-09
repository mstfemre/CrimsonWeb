from alembic import context

from crimsonweb.api.database import Base, Repository


def run() -> None:
    if context.is_offline_mode():
        from crimsonweb.api.database import database_url

        context.configure(
            url=database_url(), target_metadata=Base.metadata, literal_binds=True
        )
        with context.begin_transaction():
            context.run_migrations()
        return
    supplied = context.config.attributes.get("connection")
    if supplied is not None:
        # sqlite3 legacy transaction mode does not BEGIN for DDL. An error in a
        # later revision must roll back prior batch tables and version changes.
        if not supplied.connection.dbapi_connection.in_transaction:
            supplied.exec_driver_sql("BEGIN IMMEDIATE")
        context.configure(
            connection=supplied,
            target_metadata=Base.metadata,
            compare_type=True,
            transactional_ddl=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    else:
        repository = Repository()
        try:
            with repository.engine.begin() as connection:
                if not connection.connection.dbapi_connection.in_transaction:
                    connection.exec_driver_sql("BEGIN IMMEDIATE")
                context.configure(
                    connection=connection,
                    target_metadata=Base.metadata,
                    compare_type=True,
                    transactional_ddl=True,
                )
                with context.begin_transaction():
                    context.run_migrations()
        finally:
            repository.close()


run()
