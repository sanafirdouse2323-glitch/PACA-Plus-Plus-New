# Sample PACA policies

This directory contains a minimal example DSL policy.

```text
permit readFile when user.role == admin and user.department == engineering with obligation audit_log(user.id)
```

It demonstrates: a permit effect, a two-attribute condition, and an attached audit obligation.
