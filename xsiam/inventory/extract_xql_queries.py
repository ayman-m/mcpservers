
import json
import os
import re

def clean_query(query):
    if not query:
        return ""
    # Remove carriage returns
    query = query.replace('\r', '')
    # Replace multiple newlines with a single newline
    query = re.sub(r'\n\s*\n', '\n', query)
    # Strip leading/trailing whitespace
    return query.strip()

def extract_correlation_rules(json_data):
    extracted = []
    for rule in json_data:
        query = rule.get('xql_query')
        name = rule.get('name', 'Unnamed Rule')
        if query:
            extracted.append({
                'name': name,
                'query': clean_query(query),
                'source': 'Correlation Rule'
            })
    return extracted

def extract_dashboards(json_data):
    extracted = []
    dashboards = json_data.get('dashboards_data', [])
    for dashboard in dashboards:
        dashboard_name = dashboard.get('name', 'Unnamed Dashboard')
        layout = dashboard.get('layout', [])
        for row in layout:
            widgets = row.get('data', [])
            for widget in widgets:
                widget_data = widget.get('data', {})
                # Check directly if it is a Custom XQL widget
                if widget_data.get('type') == 'Custom XQL':
                    query = widget_data.get('phrase')
                    if query:
                         # Use widget title or key if available, otherwise just Dashboard name
                        title = widget_data.get('title', 'Custom XQL Widget')
                        full_name = f"{dashboard_name} - {title}"
                        
                        # Filter out OLD widgets
                        if "OLD" in full_name:
                            continue
                            
                        extracted.append({
                            'name': full_name,
                            'query': clean_query(query),
                            'source': 'Dashboard'
                        })
    return extracted

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    corr_rules_path = os.path.join(script_dir, 'correlation_rules.json')
    dashboards_path = os.path.join(script_dir, 'dashboards.json')
    output_path = os.path.join(script_dir, 'xqlexamples.md')
    
    all_queries = []

    # Process Correlation Rules
    if os.path.exists(corr_rules_path):
        try:
            with open(corr_rules_path, 'r') as f:
                data = json.load(f)
                all_queries.extend(extract_correlation_rules(data))
        except json.JSONDecodeError as e:
            print(f"Error decoding {corr_rules_path}: {e}")
    else:
        print(f"Warning: {corr_rules_path} not found.")

    # Process Dashboards
    if os.path.exists(dashboards_path):
        try:
            with open(dashboards_path, 'r') as f:
                data = json.load(f)
                all_queries.extend(extract_dashboards(data))
        except json.JSONDecodeError as e:
             print(f"Error decoding {dashboards_path}: {e}")
    else:
        print(f"Warning: {dashboards_path} not found.")

    # Write to Markdown
    with open(output_path, 'w') as f:
        f.write("# XQL Query Examples\n\n")
        
        for item in all_queries:
            f.write(f"### {item['name']}\n\n")
            f.write("```sql\n")
            f.write(item['query'])
            f.write("\n```\n\n")
            f.write("---\n\n")
    
    print(f"Successfully extracted {len(all_queries)} queries to {output_path}")

if __name__ == "__main__":
    main()
