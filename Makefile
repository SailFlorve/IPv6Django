.PHONY: zip
zip:
	@rm -f run.zip
	@zip -r run.zip . -x \
		'.git/*' \
		'venv/*' \
		'.idea/*' \
		'__pycache__/*' \
		'*/__pycache__/*' \
		'*/*/__pycache__/*' \
		'result/*' \
		'upload/*' \
		'db.sqlite3' \
		'db_debug.sqlite3' \
		'.gitignore' \
		'.DS_Store' \
		'dump.rdb'