# Contributing

Thanks for your interest in contributing! Here's how to get involved.

## Before You Start

1. Browse the [open issues](https://github.com/CodingCru/django-cognito-auth/issues) and find one tagged `good first issue`
2. Comment on the issue: "I'd like to work on this" — wait to be assigned before starting
3. Don't open a PR without a linked issue

## Local Setup

```bash
pip install -e ".[dev]"
pytest
ruff check .
mypy src
```

## Submitting a PR

1. Fork the repo and create a branch from `main`
2. Make your changes — keep comments to the non-obvious "why," not restating what the code does
3. Make sure `pytest`, `ruff check .`, and `mypy src` all pass
4. Open a PR back to `main` with `Fixes #<issue-number>` in the description
5. Wait for a review before merging
