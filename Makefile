.PHONY: format lint typecheck test test-integration evaluate-sample demo

format:
	ruff format src tests

lint:
	ruff check src tests

typecheck:
	mypy src

test:
	pytest

test-integration:
	pytest -o addopts= -m integration

evaluate-sample:
	vuln-agent evaluate all --config configs/evaluation.yaml --sample-size 30 --offline

demo:
	vuln-agent demo
