#!/usr/bin/env python3

import argparse
import socket
import struct
import sys
import os

MAX_MSG_SIZE = 2048
OPCODE_USER_OPERATION = 0x01
OPCODE_DELETE_REMOTE_FILE = 0x02
OPCODE_MAKE_REMOTE_DIR = 0x05

USER_FLAG_LOGIN = 0x00

def build_login_packet(username, password):
    username_bytes = username.encode()
    password_bytes = password.encode()
    username_len = len(username_bytes)
    password_len = len(password_bytes)

    packet = struct.pack("!BBHHHHI", 
                         OPCODE_USER_OPERATION, USER_FLAG_LOGIN, 0,
                         username_len, password_len, 0, 0)
    packet += username_bytes + password_bytes
    return packet

def build_delete_packet(session_id, filename):
    name_bytes = filename.encode()
    name_len = len(name_bytes)
    return struct.pack("!BHI", OPCODE_DELETE_REMOTE_FILE, name_len, session_id) + name_bytes

def build_mkdir_packet(session_id, dirname):
    dir_bytes = dirname.encode()
    dir_len = len(dir_bytes)
    return struct.pack("!BHIH", OPCODE_MAKE_REMOTE_DIR, 0, dir_len, session_id) + dir_bytes

def interactive_mode(ip, port):
    print("Capstone Client Interactive Mode")
    session_id = None

    while True:
        try:
            cmd = input("capstone> ").strip().split()
            if not cmd:
                continue

            if cmd[0] in ['quit', 'exit']:
                print("Exiting...")
                break
            elif cmd[0] == 'login' and len(cmd) == 3:
                username, password = cmd[1], cmd[2]
                packet = build_login_packet(username, password)
                with socket.create_connection((ip, port)) as sock:
                    sock.sendall(packet)
                    response = sock.recv(MAX_MSG_SIZE)
                    if len(response) >= 6:
                        return_code, _, session_id = struct.unpack("!BBI", response[:6])
                        if return_code == 0x01:
                            print(f"Login successful. Session ID: {session_id}")
                        else:
                            print(f"Login failed. Code: {hex(return_code)}")
                    else:
                        print("Incomplete response from server.")
            elif cmd[0] == 'l_delete' and len(cmd) == 2:
                try:
                    os.remove(cmd[1])
                    print(f"Local file '{cmd[1]}' deleted.")
                except Exception as e:
                    print(f"Error deleting local file: {e}")
            elif cmd[0] == 'l_ls':
                path = cmd[1] if len(cmd) > 1 else "."
                try:
                    for entry in os.listdir(path):
                        print(entry)
                except Exception as e:
                    print(f"Error listing local directory: {e}")
            elif cmd[0] == 'l_mkdir' and len(cmd) == 2:
                try:
                    os.makedirs(cmd[1], exist_ok=True)
                    print(f"Local directory '{cmd[1]}' created.")
                except Exception as e:
                    print(f"Error creating local directory: {e}")
            elif cmd[0] == 'mkdir' and len(cmd) == 2:
                if session_id is None:
                    print("Login required.")
                    continue
                packet = build_mkdir_packet(session_id, cmd[1])
                with socket.create_connection((ip, port)) as sock:
                    sock.sendall(packet)
                    response = sock.recv(1)
                    code = response[0]
                    if code == 0x01:
                        print("Remote directory created.")
                    else:
                        print(f"Failed to create remote directory. Code: {hex(code)}")
            elif cmd[0] == 'delete' and len(cmd) == 2:
                if session_id is None:
                    print("Login required.")
                    continue
                packet = build_delete_packet(session_id, cmd[1])
                with socket.create_connection((ip, port)) as sock:
                    sock.sendall(packet)
                    response = sock.recv(1)
                    code = response[0]
                    if code == 0x01:
                        print("Remote file deleted.")
                    else:
                        print(f"Failed to delete remote file. Code: {hex(code)}")
            elif cmd[0] == 'help':
                print("""Available commands:
  login <user> <pass>   - Log in to server
  delete <path>         - Delete file on server
  mkdir <path>          - Make remote directory
  l_delete <path>       - Delete file locally
  l_ls [path]           - List local directory
  l_mkdir <path>        - Make local directory
  quit / exit           - Exit client
  help                  - Show this help message
""")

            else:
                print(f"Command not implemented: {' '.join(cmd)}")
        except (EOFError, KeyboardInterrupt):
            print("\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Capstone File Transfer Client")
    parser.add_argument("--ip", help="Server IP address", required=True)
    parser.add_argument("--port", type=int, help="Server port", required=True)
    parser.add_argument("--cmd", nargs=argparse.REMAINDER, help="Run a single command and exit")

    args = parser.parse_args()

    if args.cmd:
        print(f"Command line mode: {' '.join(args.cmd)}")
    else:
        interactive_mode(args.ip, args.port)

if __name__ == "__main__":
    main()
