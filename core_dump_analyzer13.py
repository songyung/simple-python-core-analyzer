#!/usr/bin/env python3

import subprocess
import sys
import re

def run_gdb(core_file, executable):
    gdb_command = f"gdb --batch -ex 'thread apply all bt' {executable} {core_file}"
    process = subprocess.Popen(gdb_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        error_message = stderr.decode().strip() or "GDB failed to execute properly. Please check your core file and executable path."
        raise RuntimeError(error_message)
    return stdout.decode()

def analyze_stack_trace(stack_trace):
    issues = []

    # Segmentation Fault Detected
    segfault_pattern = re.compile(r"signal 11, Segmentation fault|Segmentation fault")
    if segfault_pattern.search(stack_trace):
        issues.append("Segmentation fault detected. This could indicate a buffer overrun, memory corruption issue, or invalid memory access.")

    # Null Pointer Dereference
    npd_pattern = re.compile(r"0x0\s")
    if npd_pattern.search(stack_trace):
        issues.append("Potential null pointer dereference found.")

    # Buffer Overflow - Looking for usage of risky functions and suggesting safer alternatives
    bo_pattern = re.compile(r"(strcpy|sprintf|strcat|gets)\(")
    if bo_pattern.search(stack_trace):
        issues.append("Potential buffer overflow risk detected. Consider using safer alternatives like strncpy, snprintf, strncat, or fgets.")

    # Deadlock Detection - Simplistic approach with a note on potential for false positives
    deadlock_pattern = re.compile(r"pthread_mutex_lock")
    if deadlock_pattern.search(stack_trace):
        issues.append("Potential deadlock detected. This heuristic might yield false positives. A deeper analysis is recommended for accurate identification.")
    
    # Stack Overflow Detection
    function_calls = {}
    for line in stack_trace.split('\n'):
        match = re.search(r'at (\w+)', line)
        if match:
            function_name = match.group(1)
            if function_name in function_calls:
                function_calls[function_name] += 1
            else:
                function_calls[function_name] = 1

    for call_count in function_calls.values():
        if call_count > 10:  # Example threshold
            issues.append("Potential stack overflow detected due to deep recursion.")
            break

    return issues if issues else ["No common issues detected."]

def generate_report(issues, stack_trace):
    report = "Analysis Report:\n"
    report += "=================\n"
    
    if issues:
        report += "Summary of Detected Issues:\n"
        for issue in issues:
            report += f"- {issue}\n"
        report += "\n"
    else:
        report += "No common issues detected.\n\n"
    
    report += "Stack Trace (excerpt):\n"
    report += "----------------------\n"
    stack_trace_lines = stack_trace.split('\n')
    report += "\n".join(stack_trace_lines[:15])
    report += "\n\n... (truncated for brevity. Please review the full stack trace for more details)"
    return report

if __name__ == "__main__":
    try:
        if len(sys.argv) < 3:
            print("Missing arguments. Please provide the path to the core dump and the executable.")
            sys.exit(1)
        core_file = sys.argv[1]
        executable = sys.argv[2]

        stack_trace = run_gdb(core_file, executable)
        issues = analyze_stack_trace(stack_trace)
        report = generate_report(issues, stack_trace)
        print(report)
    except RuntimeError as e:
        print(f"Error: {e}")

