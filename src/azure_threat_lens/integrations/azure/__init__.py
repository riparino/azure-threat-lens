"""Azure API integrations.

Clients are imported lazily to avoid loading azure-identity until actually used.
"""
# Intentionally not eagerly importing to keep startup fast and avoid
# import failures in environments where azure-identity is optional.
