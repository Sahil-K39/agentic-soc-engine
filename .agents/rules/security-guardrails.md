# Security and Agent Guardrails

This document establishes the developer and agent guardrails for the `cyber-threat-dashboard` project. These rules ensure that any future modifications remain secure, fast, and cost-effective.

## 1. Speed & Token Efficiency Guardrails
- **Minimal File Reads:** When reading logs or modifying files, target specific line numbers or use incremental updates. Do not read the entire `mock_auth.log` if it grows large.
- **Clean Backend Payloads:** Keep API responses lean. Send only the necessary fields for rendering.
- **No Heavy Libraries:** Do not install large external packages for the backend or frontend (e.g., Lodash, Express, TailwindCSS) unless requested. Stick to standard library modules in Python and vanilla CSS/JS.

## 2. Backend Security Guardrails
- **Input Validation:** All endpoints accepting parameters (such as `POST /api/block`) must sanitize and validate input.
  - IP addresses must match a strict IPv4 regex: `^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`.
  - Blocked IP inputs must be checked to prevent buffer overflows or code injections.
- **Directory Traversal Prevention:** The file server in `app.py` must explicitly resolve the request path and verify that it lies within the `cyber-threat-dashboard/` workspace. It must reject any path containing `..` or leading outside the root.
- **Resource Constraints:** The mock log simulator thread must have a maximum log file size limit (e.g., 5000 lines). Once the limit is reached, it should truncate or rotate `mock_auth.log` to prevent disk space exhaustion.

## 3. Frontend Security & Robustness Guardrails
- **XSS Prevention:** Log contents rendered in `index.html` must be escaped before being injected into the DOM (use `textContent` or escape HTML characters). Do not write raw log lines directly using `innerHTML`.
- **Throttling & Polling:** Polling intervals must be set to a reasonable rate (minimum 3 seconds). If the page becomes inactive (e.g., page visibility changes to hidden), pause the polling loop to conserve resources.
- **CSS Architecture:** Maintain modern, clean CSS standards (flexbox/grid, CSS variables, logical properties) within `index.html` instead of writing inline style sheets or ad-hoc style tags in elements.
