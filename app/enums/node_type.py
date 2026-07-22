from enum import Enum


class NodeType(str, Enum):
    # Program structure
    PROGRAM = "Program"
    MODULE = "Module"
    FILE = "File"
    
    # Functions and classes
    FUNCTION = "Function"
    CLASS = "Class"
    METHOD = "Method"
    PARAMETER = "Parameter"
    VARIABLE = "Variable"
    ASSIGNMENT = "Assignment"
    RETURN = "Return"
    BINARY_OP = "BinaryOperation"
    IDENTIFIER = "Identifier"
    
    # Security-critical imports (UPDATED)
    IMPORT = "Import"
    
    # Async/await (NEW)
    ASYNC_FUNCTION = "AsyncFunction"
    AWAIT = "Await"
    
    # Lambda functions (NEW)
    LAMBDA = "Lambda"
    
    # Comprehensions (NEW)
    LIST_COMP = "ListComp"
    DICT_COMP = "DictComp"
    SET_COMP = "SetComp"
    GENERATOR_EXP = "GeneratorExp"
    
    # Exception handling (NEW)
    TRY = "Try"
    EXCEPT = "Except"
    RAISE = "Raise"
    
    # Scope declarations (NEW)
    GLOBAL = "Global"
    NONLOCAL = "Nonlocal"
    
    # Attributes (NEW)
    ATTRIBUTE = "Attribute"
    
    # Control flow
    IF_STATEMENT = "IfStatement"
    FOR_STATEMENT = "ForStatement"
    WHILE_STATEMENT = "WhileStatement"
    TRY_STATEMENT = "TryStatement"
    EXCEPT_HANDLER = "ExceptHandler"
    
    # Expressions
    CALL_EXPRESSION = "CallExpression"
    ATTRIBUTE_ACCESS = "AttributeAccess"
    MEMBER_ACCESS = "MemberAccess"           # JS/TS obj.prop.method chains
    SUBSCRIPT = "Subscript"                  # Array/dict subscript like arr[i] or sys.argv[1]
    LITERAL = "Literal"
    EXPRESSION = "Expression"                # Generic expression
    
    # String operations (NEW - for injection detection)
    FSTRING = "FString"                      # Python f"...{var}..."
    STRING_CONCAT = "StringConcat"           # "a" + b or `template ${var}`
    STRING_FORMAT = "StringFormat"           # "{}".format(var)
    STRING_PERCENT = "StringPercent"         # "%s" % var
    STRING_JOIN = "StringJoin"               # "".join([...])
    STRING_TEMPLATE = "StringTemplate"       # string.Template
    TEMPLATE_LITERAL = "TemplateLiteral"     # JS/TS `...${var}...`
    
    # Security-specific nodes (NEW)
    TAINT_SOURCE = "TaintSource"             # User input entry point
    SENSITIVE_SINK = "SensitiveSink"         # Dangerous operation
    AUTH_CHECK = "AuthCheck"                 # Authentication verification
    PERMISSION_CHECK = "PermissionCheck"     # Authorization check
    SANITIZER = "Sanitizer"                  # Input sanitization
    VALIDATOR = "Validator"                  # Input validation
    
    # HTTP and APIs
    HTTP_ENDPOINT = "HttpEndpoint"
    HTTP_REQUEST = "HttpRequest"
    HTTP_RESPONSE = "HttpResponse"
    ROUTE_DECORATOR = "RouteDecorator"
    MIDDLEWARE = "Middleware"
    AUTH_GUARD = "AuthGuard"
    
    # Database
    ORM_QUERY = "ORMQuery"
    SQL_QUERY = "SQLQuery"
    DB_CONNECTION = "DBConnection"
    DB_CURSOR = "DBCursor"
    
    # JavaScript/TypeScript specific
    REACT_COMPONENT = "ReactComponent"
    JSX_ELEMENT = "JSXElement"
    TS_INTERFACE = "TSInterface"
    ARROW_FUNCTION = "ArrowFunction"
    PROMISE = "Promise"
    
    # External calls
    EXTERNAL_CALL = "ExternalCall"           # HTTP client, subprocess, etc.
    SYSTEM_CALL = "SystemCall"               # OS commands
    EVAL_CALL = "EvalCall"                   # eval(), exec(), Function()
    
    # DOM (for XSS detection)
    DOM_ELEMENT = "DOMElement"
    DOM_PROPERTY = "DOMProperty"
    
    TEMPLATE_NODE = "TemplateNode"
    UNKNOWN = "Unknown"
