FROM public.ecr.aws/lambda/python:3.11

# Copy the whole project so the handler can import aws/, features/, models/.
COPY requirements.txt ${LAMBDA_TASK_ROOT}/requirements.txt
RUN pip install --only-binary=:all: -r ${LAMBDA_TASK_ROOT}/requirements.txt --target ${LAMBDA_TASK_ROOT}
# The Lambda base image's system SQLite predates 3.8.3, which SQLAlchemy's
# sqlite dialect requires (it registers a REGEXP function with
# deterministic=True on every connect). pysqlite3-binary bundles its own
# modern SQLite; handler.py swaps it in for the stdlib sqlite3 module.
RUN pip install --only-binary=:all: pysqlite3-binary --target ${LAMBDA_TASK_ROOT}

COPY aws/ ${LAMBDA_TASK_ROOT}/aws/
COPY data/ ${LAMBDA_TASK_ROOT}/data/
COPY features/ ${LAMBDA_TASK_ROOT}/features/
COPY models/ ${LAMBDA_TASK_ROOT}/models/
COPY genai/ ${LAMBDA_TASK_ROOT}/genai/
COPY infra/lambda/scorer/handler.py ${LAMBDA_TASK_ROOT}/handler.py

CMD ["handler.handler"]
