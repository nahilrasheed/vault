A regular expression, sometimes referred to as rational expression, is a sequence of characters that specifies a match pattern in text. Usually such patterns are used by string-searching algorithms for "find" or "find and replace" operations on strings, or for input validation.
- https://regex101.com

`re` module in python
### Symbols for character types

| Symbol | Description                                                                                                          | Example Match                     |
| ------ | -------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| \w     | Matches any **alphanumeric character** (A-z, 0-9) OR an **underscore** (_).                                          | In "ID_A17", matches I,D,_,A,1,7. |
| \d     | Matches any **single digit** (0-9).                                                                                  | In "ID_A17", matches 1,7.         |
| \s     | Matches any **single whitespace** character (space, tab, newline).                                                   | Matches the space in "user 1".    |
| .      | Matches **any character** (letters, digits, symbols, spaces), except for a newline.                                  |                                   |
| \.     | Matches the **literal period character** (.). The backslash \ is necessary to escape the special meaning of the dot. |                                   |

### Symbols to quantify occurrences

| Symbol | Description                                                  | Example                                             |
| ------ | ------------------------------------------------------------ | --------------------------------------------------- |
| +      | **One or more** occurrences. (e.g., \d+ matches 1,12,12345). |                                                     |
| *      | **Zero, one, or more** occurrences.                          |                                                     |
| {n}    | **Exactly n** occurrences.                                   | \d{4} matches four consecutive digits (e.g., 1234). |
| {n,n}  | Between **m (minimum) and n (maximum)** occurrences.         | \d{1,3} matches 1,12, or 123.                       |

