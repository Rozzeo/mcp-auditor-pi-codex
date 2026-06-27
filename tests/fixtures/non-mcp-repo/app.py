"""A plain Python module with no MCP server. Should report is_mcp_server: false."""


def add(a, b):
    return a + b


def main():
    print(add(2, 3))


if __name__ == "__main__":
    main()
