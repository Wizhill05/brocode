from brocode.settings import Settings


def test_public_defaults_do_not_depend_on_a_local_model_service(tmp_path, monkeypatch):
    monkeypatch.setenv("BROCODE_ROOT", str(tmp_path))
    for name in ("OPENAI_BASE_URL", "VISION_MODEL", "DEFAULT_MODEL", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    settings = Settings.load()
    assert settings.base_url == "https://api.openai.com/v1"
    assert settings.model == "gpt-4.1"
    assert settings.api_key == ""
    assert settings.state_dir == tmp_path / "var"


def test_operator_endpoint_and_model_configuration_preserved(tmp_path, monkeypatch):
    monkeypatch.setenv("BROCODE_ROOT", str(tmp_path))
    monkeypatch.setenv("OPENAI_BASE_URL", "https://models.example.test/v1")
    monkeypatch.setenv("VISION_MODEL", "operator-model")
    settings = Settings.load()
    assert settings.base_url == "https://models.example.test/v1"
    assert settings.model == "operator-model"
