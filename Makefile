.PHONY: update-hashes

update-hashes:
	pip-compile --generate-hashes --output-file constraints-hashed.txt requirements.txt
	pip-compile --generate-hashes --allow-unsafe --output-file constraints-dev-hashed.txt requirements.txt requirements-dev.txt
