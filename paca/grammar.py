"""Grammar definition for the PACA++ policy DSL.

This grammar stays intentionally compact. It is meant to document the supported
language and to act as a ground truth for the parser implementation.
"""

PACA_GRAMMAR = r'''
start: policy
policy: effect action ["when" conditions] ["with" "obligation" obligation]

?effect: "permit" | "deny"
action: NAME
conditions: condition ( ("and" | "or") condition )*
condition: ENTITY "." ATTRIBUTE op VALUE
obligation: NAME ["(" [VALUE] ")"]

ENTITY: NAME
ATTRIBUTE: NAME
op: "==" | "!=" | ">=" | "<=" | ">" | "<"
VALUE: STRING | NUMBER | NAME
NAME: /[A-Za-z_][A-Za-z0-9_.-]*/
STRING: /"[^"]*"|\'[^\']*\'/
NUMBER: /[0-9]+(\.[0-9]+)?/
%ignore /\s+/
'''

__all__ = ["PACA_GRAMMAR"]
