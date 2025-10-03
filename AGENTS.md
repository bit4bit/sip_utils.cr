# Coding Guidelines

* Prioritize code correctness and clarity. Speed and efficiency are secondary priorities unless otherwise specified.
* Avoid creative additions unless explicitly requested.
* Think carefully before choosing names for functions, variables, or modules.
* Write short, clear, and concise code.
* Use functional paradigms for code organization.
* Do not add unnecessary code.
* Do not add additional robustness unless explicitly requested.
* Do not create examples unless explicitly requested.

# Program

* To execute run first `shards build`.

# Crystal Lang guidelines

* Use interpolation for string concatenation `%q[]`.
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
* Class initialization should not have side effects.
* Format code using `crystal tool format`.
