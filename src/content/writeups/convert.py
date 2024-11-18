# from
# ---
# title:      PoliCTF 2015 - Exceptionally obfuscated
# author:     beta4
# date:       2015-07-12 12:06:00
# summary:    Hiding control flow using C++ exceptions
# categories: PoliCTF2015 Reversing
# tags:
#  - PoliCTF
#  - Reversing
#  - C++
#  - Exceptions
#  - MIPS
# ---

# to

# ---
# title:      PoliCTF 2015 - Exceptionally obfuscated
# author:     beta4
# pubDate:       July 12 2015
# description:    Hiding control flow using C++ exceptions
# categories: PoliCTF2015 Reversing
# tags:
#  - PoliCTF
#  - Reversing
#  - C++
#  - Exceptions
#  - MIPS
# ---
import os
import re
from datetime import datetime

def update_md_files():
    # Loop through all files in the current directory
    for filename in os.listdir("."):
        # Process only .md files
        if filename.endswith(".md"):
            with open(filename, "r", encoding="utf-8") as file:
                lines = file.readlines()
            
            # Process the front matter
            new_lines = []
            in_front_matter = False
            for line in lines:
                # Detect start and end of front matter
                if line.strip() == "---":
                    if in_front_matter:
                        # End of front matter
                        in_front_matter = False
                    else:
                        # Start of front matter
                        in_front_matter = True
                    new_lines.append(line)
                    continue
                
                if in_front_matter:
                    if line.startswith("summary:"):
                        # Rename 'summary' to 'description'
                        line = line.replace("summary:", "description:", 1)
                    
                    if line.startswith("date:"):
                        # Convert the date format and rename 'date' to 'pubDate'
                        match = re.match(r"date:\s*(\d{4}-\d{2}-\d{2})\s*(.*)", line)
                        if match:
                            old_date = match.group(1)
                            time_part = match.group(2)
                            formatted_date = datetime.strptime(old_date, "%Y-%m-%d").strftime("%B %d %Y")
                            line = f"pubDate:       {formatted_date} {time_part}\n"
                
                new_lines.append(line)
            
            # Write the updated content back to the file
            with open(filename, "w", encoding="utf-8") as file:
                file.writelines(new_lines)

if __name__ == "__main__":
    update_md_files()
