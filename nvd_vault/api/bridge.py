"""API, доступное из JavaScript через window.pywebview.api."""


class Api:
    """
    Каждый публичный метод этого класса автоматически становится доступен
    из JS как window.pywebview.api.<имя_метода>().
    """

    def ping(self) -> str:
        """Проверка связи фронт <-> бэк."""
        return "pong: связь с Python работает"