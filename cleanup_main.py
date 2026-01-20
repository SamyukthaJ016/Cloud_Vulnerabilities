
import os

filepath = 'backend/main.py'
with open(filepath, 'r') as f:
    lines = f.readlines()

occurrences = []
for i, line in enumerate(lines):
    if '@app.post("/scan/multi-cloud")' in line:
        occurrences.append(i)

if len(occurrences) > 1:
    print(f"Found {len(occurrences)} occurrences. Removing the first one at index {occurrences[0]}")
    
    # We want to remove from occurrences[0] down to the next function definition or reasonable end
    start_idx = occurrences[0]
    end_idx = start_idx
    for i in range(start_idx + 1, len(lines)):
        if i in occurrences[1:]:
            break
        if lines[i].startswith('@app.') or lines[i].startswith('async def ') or lines[i].startswith('def '):
            if i > start_idx + 2: # Give some room for the current function's header
                end_idx = i
                break
        end_idx = i

    print(f"Deleting lines {start_idx} to {end_idx}")
    new_lines = lines[:start_idx] + lines[end_idx:]
    
    with open(filepath, 'w') as f:
        f.writelines(new_lines)
    print("Successfully removed duplicate endpoint.")
else:
    print("Only one occurrence found. No action needed.")
