import re
import os

def parse_datamodels(file_path):
    rules = {}
    datasets = {}
    
    current_block_name = None
    current_block_type = None # 'RULE' or 'MODEL'
    current_fields = set()
    current_calls = []

    # Regex patterns
    rule_header_re = re.compile(r'^\[RULE:\s*([\w_]+)\]', re.IGNORECASE)
    model_header_re = re.compile(r'^\[MODEL:\s*dataset\s*=\s*"?([\w_]+)"?\]', re.IGNORECASE)
    call_re = re.compile(r'(?:^|\|)\s*call\s+([\w_]+)', re.IGNORECASE)
    xdm_field_re = re.compile(r'(xdm\.[\w\.]+)\s*=', re.IGNORECASE)
    
    with open(file_path, 'r') as f:
        # Read entire file line by line
        lines = f.readlines()
        
    def save_current_block():
        nonlocal current_block_name, current_block_type, current_fields, current_calls
        if current_block_name:
            if current_block_type == 'RULE':
                rules[current_block_name] = {
                    'fields': current_fields,
                    'calls': current_calls
                }
            elif current_block_type == 'MODEL':
                datasets[current_block_name] = {
                    'fields': current_fields,
                    'calls': current_calls
                }
        
    for line in lines:
        line = line.strip()
        
        # Check for headers
        rule_match = rule_header_re.match(line)
        model_match = model_header_re.match(line)
        
        if rule_match or model_match:
            save_current_block()
            current_fields = set()
            current_calls = []
            
            if rule_match:
                current_block_name = rule_match.group(1)
                current_block_type = 'RULE'
            else:
                current_block_name = model_match.group(1)
                current_block_type = 'MODEL'
            continue
            
        # Check for calls
        call_match = call_re.search(line)
        if call_match:
            current_calls.append(call_match.group(1))
            
        # Check for XDM assignments
        # Use findall because one line can have multiple assignments if comma separated?
        # Usually alter statements are multiline or comma separated functions.
        # But regex 'xdm.field =' should catch distinct assignments.
        # Wait, lines often look like: xdm.field = value,
        # findall is safer.
        fields = xdm_field_re.findall(line)
        for field in fields:
            current_fields.add(field)
            
    # Save last block
    save_current_block()
    
    return rules, datasets

def resolve_fields(block_data, rules):
    """
    Recursively resolve fields including those from called rules.
    """
    all_fields = set(block_data['fields'])
    for called_rule in block_data['calls']:
        if called_rule in rules:
            # Recursively resolve the called rule first if needed, 
            # but simpler is just to grab its fields + its calls' fields.
            # However, circular dependency risk? Unlikely in this DSL.
            # Let's just do a simple expansion.
            # Assuming rules don't call other rules deeply or circularly for now.
            # Actually, ngfw_standalone doesn't call anything.
            # But let's support 1 level of depth at least or use recursion.
            
            rule_fields = resolve_fields(rules[called_rule], rules)
            all_fields.update(rule_fields)
            
    return all_fields

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_path = os.path.join(script_dir, 'datamodels.md')
    output_path = os.path.join(script_dir, 'dataset_fields.md')
    
    if not os.path.exists(input_path):
        print(f"Error: {input_path} not found.")
        return
        
    rules, datasets = parse_datamodels(input_path)
    
    # Resolve fields for all datasets
    resolved_datasets = {}
    for name, data in datasets.items():
        resolved_datasets[name] = resolve_fields(data, rules)
        
    # Sort datasets by name
    sorted_names = sorted(resolved_datasets.keys())
    
    with open(output_path, 'w') as f:
        f.write("# Dataset XDM Field Mappings\n\n")
        
        for name in sorted_names:
            fields = sorted(list(resolved_datasets[name]))
            if not fields:
                continue
                
            f.write(f"## {name}\n")
            # f.write(f"Raw fields count: {len(fields)}\n\n")
            for field in fields:
                f.write(f"- {field}\n")
            f.write("\n")
            
    print(f"Successfully wrote field mappings to {output_path}")

if __name__ == "__main__":
    main()
