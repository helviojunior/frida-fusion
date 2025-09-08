
class SilentKillError(Exception):
    def __init__(self, *args, **kwargs):
        # args -> vão para a Exception (ex.: a mensagem)
        # kwargs -> metadados opcionais seus
        self.meta = kwargs
        self._msg = kwargs.get("message") or ""
        if args is not None and len(args) > 0 and self._msg == "":
            self._msg = args[0]
        super().__init__(*args)

    def __str__(self):
        if self._msg != "":
            return self._msg
        else:
            return str(super(SilentKillError, self).__str__())

    def __repr__(self):
        return str(self)
