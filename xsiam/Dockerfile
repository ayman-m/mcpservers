FROM demisto/python3:3.12.12.6204436




# Copy requirements and install dependencies
COPY requirements.txt .
COPY dataset_fields.md /mcp-resources/
COPY xqlexamples.md /mcp-resources/
COPY xql_doc.md /mcp-resources/
RUN pip install --no-cache-dir -r requirements.txt

