
class Role:
    @classmethod
    def get_name(cls):
        return cls.__name__.lower()

    @classmethod
    def has_scopes(cls, scopes: list[str]) -> bool:
        required_scopes = set(scopes)
        available_scopes = set(cls.SCOPES)

        for scope in required_scopes:
            # First, check if the scope is available
            if scope in available_scopes:
                # Exact match, on to the next scope
                continue

            # If not, check if there's a wildcard permission for this action
            scope_parts = scope.split(":")
            if len(scope_parts) != 2:
                return False  # Invalid scope format
            action, resource = scope_parts
            if f"{action}:*" not in available_scopes:
                return False  # No wildcard permission for this action
        # All scopes are available
        return True

class Admin(Role):
    SCOPES = ["read:*", "write:*", "delete:*", "update:*", "execute:*"]
    DESCRIPTION = "do everything"