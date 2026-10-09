FROM python:3.13-slim

COPY pyproject.toml /src/
COPY deorbit /src/deorbit
RUN pip install --no-cache-dir --root-user-action=ignore /src

# The server reads ./deorbit.yml and resolves the relative paths in it, such as
# certs/, against that file's directory. Both are mounted here at run time.
WORKDIR /data

EXPOSE 3443 8080

# As PID 1, Python ignores SIGTERM; SIGINT closes the robot sessions and exits.
STOPSIGNAL SIGINT

CMD ["python", "-m", "deorbit"]
