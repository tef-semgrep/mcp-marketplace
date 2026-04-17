# Semgrep MCP Marketplace

INTERNAL DEMO ONLY. 

This repo is where the Semgrep [Plugin Marketplace](https://code.claude.com/docs/en/plugin-marketplaces) (`semgrep`) and the Semgrep [Plugin](https://code.claude.com/docs/en/plugins) (`semgrep-plugin@semgrep`) live.

To use the Semgrep plugin:
1. Start a Claude Code instance by running:
    ```
    claude
    ```
1. Add the Semgrep marketplace by running the following command in Claude:
    ```
    /plugin marketplace add tef-semgrep/mcp-marketplace
    ```
1. Install the plugin from the marketplace:
    ```
    /plugin install semgrep-plugin@semgrep
    ```
1. If it still doesn't work, try enabling the plugin:
    ```
    /plugin enable semgrep-plugin@semgrep
    ```

## Contributing

This plugin is managed by the [mcp-marketplace-template](https://github.com/semgrep/mcp-marketplace-template) repository. Changes should be made there and synced via automated PRs.
