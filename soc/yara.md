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

## Conditions

| Boolean operators | Relational operators | Arithmetic operators | Bitwise operators | Keywords     |
| ----------------- | -------------------- | -------------------- | ----------------- | ------------ |
| and               | >=                   | +                    | &                 | 1 of them    |
| or                | <=                   | -                    | \|                | any of them  |
| not               | <                    | \*                   | <<                | none of them |
|                   | >                    | \\                   | >>                | contains     |
|                   | ==                   | %                    | \~                | icontains    |
|                   | !=                   |                      | ^                 | startswith   |
|                   |                      |                      |                   | istartswith  |
|                   |                      |                      |                   | endswith     |
|                   |                      |                      |                   | iendswith    |
|                   |                      |                      |                   | iequals      |
|                   |                      |                      |                   | matches      |
|                   |                      |                      |                   | not defined  |
|                   |                      |                      |                   | filesize     |

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
