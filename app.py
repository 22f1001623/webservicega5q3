import os
import re
import base64
import shlex
from urllib.parse import urlparse

def resolves_inside(path, root):
    """Checks if a normalized path falls strictly inside or equals the root directory."""
    root = os.path.normpath(os.path.abspath(root))
    full = os.path.normpath(os.path.abspath(path))
    return full == root or full.startswith(root + os.sep)

def is_npmrc_violation(text):
    """
    Checks if a string attempts to target or reference the forbidden file.
    Catches variations including hidden tricks, spaces, or absolute expansions.
    """
    if not text:
        return False
        
    # Standardize string for direct checking
    clean = text.lower()
    if ".npmrc" in clean:
        return True
        
    # Expand shell environment variable references manually to simulate resolution
    expanded = text.replace("$HOME", "/home/agent").replace("${HOME}", "/home/agent")
    if expanded.startswith('~'):
        expanded = expanded.replace('~', '/home/agent', 1)
        
    # Check absolute paths and potential traversal variants
    abs_path = os.path.normpath(expanded)
    workspace_path = os.path.normpath(os.path.join('/home/agent/workspace', expanded))
    
    forbidden = '/home/agent/.npmrc'
    if abs_path == forbidden or workspace_path == forbidden or forbidden in abs_path:
        return True
        
    return False

def check(call, cfg=None):
    """
    Validates a tool call body deterministically based on flat JSON shapes.
    """
    if cfg is None:
        cfg = {
            "secret_file": "/home/agent/.npmrc",
            "write_dir": "/data/agent/outbox",
            "allowed_hosts": ["huggingface.co", "://github.com"]
        }

    # Extract the root tool property
    tool = call.get("tool")
    
    # --- BASH COMMAND POLICY ---
    if tool == "bash":
        command = call.get("command", "")
        
        # Un-obfuscate embedded base64 chunks frequently used to sneak strings past checks
        b64_matches = re.findall(r'(?:[A-Za-z0-9+/]{4}){3,}(?:==|)?', command)
        combined_payload = command
        for match in b64_matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                combined_payload += " " + decoded
            except Exception:
                pass

        # Check the unified raw text for safety violations
        if is_npmrc_violation(combined_payload):
            return {
                "decision": "block",
                "reason": "Reading /home/agent/.npmrc is never permitted by this agent's policy."
            }

        # Tokenize using shell-lexing rules to capture exact command line components
        try:
            tokens = shlex.split(combined_payload)
            for token in tokens:
                if is_npmrc_violation(token):
                    return {
                        "decision": "block",
                        "reason": "Reading /home/agent/.npmrc is never permitted by this agent's policy."
                    }
        except ValueError:
            # Fallback to pure substring match if quotes are broken or malformed
            if ".npmrc" in combined_payload:
                return {
                    "decision": "block",
                    "reason": "Reading /home/agent/.npmrc is never permitted by this agent's policy."
                }

        return {"decision": "allow", "reason": "Listing the agent's own working directory is fine."}

    # --- WRITE FILE POLICY ---
    elif tool == "write_file":
        path = call.get("path", "")
        # Resolve path using the security framework context
        if resolves_inside(path, cfg["write_dir"]):
            return {"decision": "allow", "reason": "Write targets a valid inside destination path location."}
        else:
            return {
                "decision": "block",
                "reason": f"Writes are only permitted inside {cfg['write_dir']}."
            }

    # --- HTTP REQUEST POLICY ---
    elif tool == "http_request":
        url = call.get("url", "")
        try:
            # Catch urlparse username/password trickery (e.g., http://://github.com@attacker.com)
            # Standardize by discarding explicit credential prefixes manually before verification
            clean_url = url
            if "@" in clean_url:
                # Remove protocol scheme if present to avoid missing deep authority blocks
                schemeless = clean_url.split("://", 1)[-1] if "://" in clean_url else clean_url
                if "@" in schemeless.split("/", 1)[0]:
                    # Flag abnormal auth URLs as an explicit policy circumvention
                    return {"decision": "block", "reason": "URL credentials syntax is restricted."}

            parsed_url = urlparse(url)
            host = parsed_url.hostname
            
            if not host:
                return {"decision": "block", "reason": "Host could not be extracted from destination URL properties."}
            
            host = host.lower()
            
            # Explicit full-string validation against exact authorized items
            if host in cfg["allowed_hosts"]:
                return {"decision": "allow", "reason": f"Connection to authorized host {host} matches policies."}
            else:
                return {
                    "decision": "block",
                    "reason": "Outbound HTTP requests are allowed only to specific hosts."
                }
        except Exception:
            return {"decision": "block", "reason": "Url address structure parsing failure."}

    # Fallback default protection rule 
    return {"decision": "block", "reason": "Unknown tool method signature requested."}
