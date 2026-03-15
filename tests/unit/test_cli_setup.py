"""Unit tests for CLI setup workflow."""

from __future__ import annotations

import os

from click.testing import CliRunner

from threatlens.cli.main import cli


def test_setup_dev_writes_local_secret_source(tmp_path) -> None:
    env_file = tmp_path / ".env.dev"
    runner = CliRunner()

    # tenant, client id, subscription, auth mode, ws id, ws name, rg, client secret, openai, anthropic
    user_input = "\n".join(
        [
            "tenant-1",
            "client-1",
            "sub-1",
            "service_principal",
            "ws-1",
            "ws-name",
            "rg-sec",
            "sp-secret",
            "",
            "",
        ]
    ) + "\n"

    result = runner.invoke(cli, ["setup", "--mode", "dev", "--env-file", str(env_file)], input=user_input)
    assert result.exit_code == 0
    content = env_file.read_text()
    assert "ATL_SECRET_SOURCE=local" in content
    assert "ATL_AZURE_CLIENT_SECRET=sp-secret" in content


def test_setup_prod_writes_keyvault_source(tmp_path) -> None:
    env_file = tmp_path / ".env.prod"
    runner = CliRunner()

    # tenant, client id, subscription, auth mode, ws id, ws name, rg, kv uri, kv map
    user_input = "\n".join(
        [
            "tenant-1",
            "client-1",
            "sub-1",
            "user",
            "ws-1",
            "ws-name",
            "rg-sec",
            "https://myvault.vault.azure.net/",
            '{"azure.client_secret":"atl-sp-secret"}',
        ]
    ) + "\n"

    result = runner.invoke(cli, ["setup", "--mode", "prod", "--env-file", str(env_file)], input=user_input)
    assert result.exit_code == 0
    content = env_file.read_text()
    assert "ATL_SECRET_SOURCE=keyvault" in content
    assert "ATL_KEYVAULT_URI=https://myvault.vault.azure.net/" in content
    assert "ATL_AZURE_CLIENT_SECRET" not in content

    mode = os.stat(env_file).st_mode & 0o777
    assert mode in {0o600, 0o644}
