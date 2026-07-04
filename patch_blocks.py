with open("target-esp32s3/src/main.rs", "r") as f:
    lines = f.readlines()

# Line 289 is unsafe {
lines[288] = ""
# Line 313 is }
lines[312] = ""

# Line 346 is unsafe {
lines[345] = ""
# Line 374 is }
lines[373] = ""

with open("target-esp32s3/src/main.rs", "w") as f:
    f.writelines(lines)
