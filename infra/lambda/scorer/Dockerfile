FROM public.ecr.aws/lambda/python:3.11

# Copy the whole project so the handler can import aws/, features/, models/.
COPY requirements.txt ${LAMBDA_TASK_ROOT}/requirements.txt
RUN pip install -r ${LAMBDA_TASK_ROOT}/requirements.txt --target ${LAMBDA_TASK_ROOT}

COPY aws/ ${LAMBDA_TASK_ROOT}/aws/
COPY data/ ${LAMBDA_TASK_ROOT}/data/
COPY features/ ${LAMBDA_TASK_ROOT}/features/
COPY models/ ${LAMBDA_TASK_ROOT}/models/
COPY genai/ ${LAMBDA_TASK_ROOT}/genai/
COPY infra/lambda/scorer/handler.py ${LAMBDA_TASK_ROOT}/handler.py

CMD ["handler.handler"]
