# Contributing to Splunk SPL Detection Library

First off, thank you for considering contributing! This library relies on security practitioners like you to stay ahead of emerging threats.

## 🤝 How to contribute

### 1. Add a New Detection
1.  **Fork** the repository.
2.  **Create** a branch: `git checkout -b detection/T1234-my-detection`
3.  **Copy** one of the templates:
    *   `templates/TEMPLATE_Standard_Alert.spl` (For general detections)
    *   `templates/TEMPLATE_Threat_Hunting.spl` (For hunting queries)
4.  **Write** your SPL logic.
5.  **Test** it! (See Testing Guidelines below).
6.  **Push** and submit a Pull Request.

### 2. Improve Existing Detections
*   Found a logic error?
*   Have a better way to filter false positives?
*   Want to add a missing risk scoring mapping?
*   **PRs are welcome!**

---

## 🧪 Testing Guidelines

We aim for **production-ready** code. Please verify the following before submitting:

*   **Syntax**: Does the SPL run without errors?
*   **Performance**: Does it use `tstats` where possible? Avoid broad wildcards `index=*`.
*   **CIM Compliance**: Do you use standard fields (`user`, `dest`, `src_ip`)?
*   **Documentation**: Did you fill out the Description, False Positives, and Severity sections?

---

## 📝 Pull Request Template

When submitting a PR, please provide:

```markdown
## Detection Overview
- **Name**: [Name of detection]
- **MITRE Technique**: [T####]
- **Goal**: [What does this catch?]

## Testing Support
- [ ] I have tested this query in a lab/prod environment.
- [ ] It returns results for the intended threat.
- [ ] It does NOT generate excessive noise.

## Screenshots (Optional)
[Paste screenshot of search results]
```
