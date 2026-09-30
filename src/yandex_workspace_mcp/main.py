import argparse
import sys


def main():
    # Configure redacting stderr logging before any HTTP clients can emit request logs.
    from .logging import setup_logging

    setup_logging()

    parser = argparse.ArgumentParser(description="Yandex Workspace MCP Server")
    parser.add_argument("command", choices=["serve", "doctor", "tools"], nargs="?", default="serve")
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default=None)
    args = parser.parse_args()

    from .config import Settings, get_settings

    settings = Settings(mcp_transport=args.transport) if args.transport else get_settings()

    if args.command == "doctor":
        print("MCP specification ......... 2026-07-28")
        print("MCP SDK ................... v2.x")
        print(f"MCP profile ............... {settings.mcp_profile}")
        print(f"Mail enabled .............. {settings.yandex_mail_enabled}")
        print(f"Disk enabled .............. {settings.yandex_disk_enabled}")
        print(f"Wiki enabled .............. {settings.yandex_wiki_enabled}")
        print(f"Disk read ................. {'ENABLED' if settings.disk_read else 'DISABLED'}")
        print(f"Wiki read ................. {'ENABLED' if settings.wiki_read else 'DISABLED'}")
        sys.exit(0)

    if args.command == "tools":
        from .server import create_application

        create_application(settings)
        print("Tools registered on the server.")
        sys.exit(0)

    from .server import create_application

    application = create_application(settings)

    transport = settings.mcp_transport
    if transport == "stdio":
        application.mcp_server.run(transport="stdio")
    elif transport == "streamable-http":
        import uvicorn

        from .server import create_http_app

        uvicorn.run(
            create_http_app(application),
            host=settings.mcp_host,
            port=settings.mcp_port,
            log_level="info",
        )


if __name__ == "__main__":
    main()
