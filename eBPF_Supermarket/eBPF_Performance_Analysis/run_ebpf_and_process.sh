#!/bin/bash

# Function to handle Ctrl+C
function ctrl_c() {
    echo "Ctrl+C detected. Stopping ebpf_performance..."
    pkill -f "ebpf_performance"  # Use -f option to match the complete command line

    # Step 2: Add a short delay to ensure all data is written to output.txt
    sleep 2  # Increase delay to 2 seconds to ensure file write completion

    # Step 3: Check if output.txt exists and is not empty
    if [ -f "output.txt" ]; then
        echo "Output file exists."
    else
        echo "Output file does not exist."
        exit 1
    fi

    if [ -s "output.txt" ]; then
        echo "Output file generated successfully. File size: $(du -h output.txt)"

        # Step 4: Run Python script to process the data
        echo "Running Python script to process the data..."
        sudo python3 ./py/analy.py

        if [ $? -eq 0 ]; then
            echo "Python script executed successfully."
        else
            echo "Python script failed to execute."
        fi
    else
        echo "Output file exists but is empty. File size: $(du -h output.txt)"
        exit 1
    fi

    exit 0
}

# Trap Ctrl+C signal
trap ctrl_c INT

# Step 1: Run eBPF program and redirect output to output.txt in a loop
echo "Starting eBPF program..."
sudo stdbuf -oL ./ebpf_performance -a > output.txt &

# Wait for the eBPF program to be manually terminated by Ctrl+C
wait $!

# If the script reaches here without Ctrl+C, it means ebpf_performance finished by itself
echo "eBPF program finished by itself, running Python script..."
ctrl_c
