# YARA

## YARA Documentation

{% embed url="https://yara.readthedocs.io/en/stable/writingrules.html" %}

## Text Strings

```textile
rule textString
    {
      strings: 
            $1 = "This is an ASCII-encoded string" //strings are defined between double quotes
            $2 = "This is an ascii-encoded string" //not the same as $1.
            
      condition:  
            all of them 
    } 
```

## No Case

```javascript
rule noCaseTextString
    {
      strings: 
            $1 = "This is an ASCII-encoded string" nocase
            
      condition:  
            $1
    } 
```

## Wide-Character Strings

```javascript
rule wideTextString
    {
      strings: 
            $1 = "tryhackme" wide // will match with t\x00r\x00y\x00h\x00a\x00c\x00k\x00m\x00e\x00 
            
      condition:  
            $1
    } 
```

## HexDecimal Strings

```javascript
rule hexString
    {
      strings: 
            $1 = { E2 34 B6 C8 A3 FB } // Hexadecimal strings are defined between {}
            
      condition:  
            $1
    } 
    
```

```javascript
rule hexStringExpanded
    {
      strings: 
            $1 = { E2 34 B6 ?? A3 FB } // The ? is a wildcard and can represent any hex value.
            $2 = { E2 34 B6 ~00 A3 FB } // The ~ is a not operator that precedes the value to exclude from the search. In this case 00.
            $3 = { E2 34 [2-4] A3 FB } // The [X-Y] construct defines a jump. This means that any value between 2 and 4 bytes can occupy this position.
            $4 = { E2 34 (C5|B5) A3 FB } // Between () alternative byte sequences can be defined separated with the boolean operator OR. The value can be B5 OR C5.       
      condition:   
             $1
    } 
```

## XOR Strings

```javascript
rule xorString
    {
      strings: 
            $1 = "http://maliciousurl.thm" xor // This line will look for all variations possible with a 1-byte XOR key
            
      condition:  
            $1
    } 
```

## Regular Expression

```javascript
rule regularExpression
        {
            strings: 
                $1 = /THM\{[a-zA-Z]{3}\}/ // This regex will match any string that starts with "THM{", ends with "}" and has 3 alphabetic characters (lower-case or upper-case) between the curly brackets.
                
            condition:  
                $1
        } 
```

## Modifiers

| Keyword      | String Types     | Summary                                                                            | Restrictions                                        |
| ------------ | ---------------- | ---------------------------------------------------------------------------------- | --------------------------------------------------- |
| `nocase`     | Text, Regex      | Ignore case                                                                        | Cannot use with `xor`, `base64`, or `base64wide`    |
| `wide`       | Text, Regex      | Emulate UTF16 by interleaving null (0x00) characters                               | None                                                |
| `ascii`      | Text, Regex      | Also match ASCII characters, only required if `wide` is used                       | None                                                |
| `xor`        | Text             | XOR text string with single byte keys                                              | Cannot use with `nocase`, `base64`, or `base64wide` |
| `base64`     | Text             | Convert to 3 base64 encoded strings                                                | Cannot use with `nocase`, `xor`, or `fullword`      |
| `base64wide` | Text             | Convert to 3 base64 encoded strings, then interleaving null characters like `wide` | Cannot use with `nocase`, `xor`, or `fullword`      |
| `fullword`   | Text, Regex      | Match is not preceded or followed by an alphanumeric character                     | Cannot use with `base64` or `base64wide`            |
| `private`    | Hex, Text, Regex | Match never included in output                                                     | None                                                |

## Conditions

| Precedence | Operator                                                                                                                                        | Description                                                                                                                                                                                                                                                                                                                                          | Associativity |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| 1          | <p>[]</p><p>.</p>                                                                                                                               | <p>Array subscripting</p><p>Structure member access</p>                                                                                                                                                                                                                                                                                              | Left-to-right |
| 2          | <p><em>-</em></p><p><em>~</em></p>                                                                                                              | <p>Unary minus</p><p>Bitwise not</p>                                                                                                                                                                                                                                                                                                                 | Right-to-left |
| 3          | <p><em>*</em></p><p>\</p><p>%</p>                                                                                                               | <p>Multiplication</p><p>Division</p><p>Remainder</p>                                                                                                                                                                                                                                                                                                 | Left-to-right |
| 4          | <p><em>+</em></p><p><em>-</em></p>                                                                                                              | <p>Addition</p><p>Subtraction</p>                                                                                                                                                                                                                                                                                                                    | Left-to-right |
| 5          | <p><em>&#x3C;&#x3C;</em></p><p><em>>></em></p>                                                                                                  | <p>Bitwise left shift</p><p>Bitwise right shift</p>                                                                                                                                                                                                                                                                                                  | Left-to-right |
| 6          | &                                                                                                                                               | Bitwise AND                                                                                                                                                                                                                                                                                                                                          | Left-to-right |
| 7          | ^                                                                                                                                               | Bitwise XOR                                                                                                                                                                                                                                                                                                                                          | Left-to-right |
| 8          | _\|_                                                                                                                                            | Bitwise OR                                                                                                                                                                                                                                                                                                                                           | Left-to-right |
| 9          | <p>&#x3C;</p><p>&#x3C;=</p><p>></p><p>>=</p>                                                                                                    | <p>Less than</p><p>Less than or equal to</p><p>Greater than</p><p>Greater than or equal to</p>                                                                                                                                                                                                                                                       | Left-to-right |
| 10         | <p>==</p><p>!=</p><p>contains</p><p>icontains</p><p>startswith</p><p>istartswith</p><p>endswith</p><p>iendswith</p><p>iequals</p><p>matches</p> | <p>Equal to</p><p>Not equal to</p><p>String contains substring</p><p>Like contains but case-insensitive</p><p>String starts with substring</p><p>Like startswith but case-insensitive</p><p>String ends with substring</p><p>Like endswith but case-insensitive</p><p>Case-insensitive string comparison</p><p>String matches regular expression</p> | Left-to-right |
| 11         | not defined                                                                                                                                     | Logical NOT Check if an expression is defined                                                                                                                                                                                                                                                                                                        | Right-to-left |
| 12         | and                                                                                                                                             | Logical AND                                                                                                                                                                                                                                                                                                                                          | Left-to-right |
| 13         | or                                                                                                                                              | Logical OR                                                                                                                                                                                                                                                                                                                                           | Left-to-right |

## Arguments

| Short Flag | Long Flag       | Description                                                          |
| ---------- | --------------- | -------------------------------------------------------------------- |
| -r         | --recursive     | Scan directories recursively                                         |
| -n         | --negate        | Print only rules that weren't matched                                |
| -S         | --print-stats   | Print metadata related to the performance and efficiency of the rule |
| -s         | --print-strings | Print the strings that were matched in a file                        |
| -X         | --print-xor-key | Print xor key and plaintext of matched strings                       |
| -v         | --version       | Show the YARA version                                                |
| -p         | --threads=N     | Use N threads to scan a directory                                    |

## YaraGen Tool

{% embed url="https://github.com/Neo23x0/yarGen" %}

how to download YaraGen tool follow steps below:

* Download the latest release from the `release` section
* Install all dependencies with `pip install -r requirements.txt`
* Run `python yarGen.py --update` to automatically download the built-in databases. They will be saved into the './dbs' subfolder (Download: `913 MB`).
* See help with `python yarGen.py --help` for more information on the command line parameters.

```shell-session
python3 yarGen.py -m <malware_sample_file_location> -o outfilesample.yar
```

## Resource&#x20;

* [How to Write Simple but Sound Yara Rules - Part 1](https://www.nextron-systems.com/2015/02/16/write-simple-sound-yara-rules/)
* [How to Write Simple but Sound Yara Rules - Part 2](https://www.nextron-systems.com/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/)
* [How to Write Simple but Sound Yara Rules - Part 3](https://www.nextron-systems.com/2016/04/15/how-to-write-simple-but-sound-yara-rules-part-3/)
