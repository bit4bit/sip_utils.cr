# Coding Guidelines

* Prioritize code correctness and clarity. Speed and efficiency are secondary priorities unless otherwise specified.
* Avoid creative additions unless explicitly requested.
* Think carefully before choosing names for functions, variables, or modules.
* Write short, clear, and concise code.
* Use functional paradigms for code organization.

# Program

* To execute run first `shards build`.

# Crystal Lang guidelines

* Use `String.build` when building multiline strings.
```
String.build do |str|
  str << "hello "
  str << 1
end
```
* Do not write code comments.
* Do not explain the implementation details.
* Always follow SOLID principles.
* Always avoid duplicated code, reuse existing code.
