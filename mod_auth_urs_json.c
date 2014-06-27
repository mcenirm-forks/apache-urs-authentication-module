/*
 * mod_auth_urs_json.c: URS OAuth2 Module
 *
 * This module contains JSON parsing code.
 *
 * Author: Peter Smith
 */

#include    "mod_auth_urs.h"

#include    "apr_hash.h"
#include    "apr_lib.h"
#include    "apr_strings.h"


#include    "http_log.h"

/*

 A typical URS user profile looks like this in json form.
 
{
    "uid":"memememe",
    "first_name":"Mini",
    "last_name":"Me",
    "email_address":"MiniMe@mine.com",
    "country":"United States",
    "city":"Riverdale",
    "state":"MD",
    "street1":"5700 Rivertech Court",
    "study_area":"Other",
    "phone":"301 851 6363",
    "user_type":"Data Provider Internal User",
    "zip":"20737",
    "affiliation":"Commercial",
    "organization":"Raytheon",
    "member_groups":["lance","echo"]
}

*/




/**
 * Internal struture (not exposed outside this module)
 * that represents a json value - its type and data.
 */
typedef struct json_value
{
    json_type type;

    void*     value; 

} json_value;


/**
 * Internal structure used to represent a json object.
 * Pointers to this structure are exposed externally,
 * but the structure details are not.
 * This structure simply contains a hash table of 
 * josn_value objects.
 */
struct json
{
    apr_hash_t*    elements;

};



/**
 * Internal method declarations.
 *
 */
static int json_read_value( apr_pool_t* pool, json_value* json_val, const char* start, const char** end );
static int json_read_string( const char* start, const char** end );
static int json_read_number( const char* start, const char** end );
static json_value* json_read_array( apr_pool_t* pool, const char* start, const char** end );
static json* json_parse_object( apr_pool_t* pool, const char* start, const char** end );
static int json_read_value( apr_pool_t* pool, json_value* json_val, const char* start, const char** end );



/************************************
 * External methods
 ************************************/


/**
 * Parse a text string into a json object.
 * @param pool the pool to use for memory allocation
 * @param json_text the text to parse
 * @return a pointer to a json object, or NULL if the text
 *         could not be parsed.
 */
json* json_parse( apr_pool_t* pool, const char* json_text )
{
    const char*  end;
    json*        json;


    json = json_parse_object(pool, json_text, &end);
    return json;
}


/**
 * Return the type of a named json member.
 * @param json the json object to search
 * @param name the name of the member whose type is to be returned
 * @return the type of the named member, or json_null if it does
 *         not exists. Note that json_null is also a valid type.
 */
json_type json_get_member_type(json* json, const char* name )
{
    json_value* p;
    
    p = (json_value*) apr_hash_get(json->elements, name, strlen(name));
    if( p == NULL ) return json_null;
    
    return p->type;
}


/**
 * Return the value of a named json member.
 * @param json the json object to search
 * @param name the name of the member whose value is to be returned
 * @return a pointer to the json member value, or NULL it the named
 *         member does not exist or is not a suitable type (e.g array)
 */
const char* json_get_member_string(json* json, const char* name )
{
    json_value* p;
    
    p = (json_value*) apr_hash_get(json->elements, name, strlen(name));
    if( p == NULL ) return NULL;
    if( p->type != json_string && 
        p->type != json_number &&
        p->type != json_boolean &&
        p->type != json_null )
    {
        return NULL;
    }

    return (const char*) (p->value);
}


/**
 * Return a named json member object.
 * @param json the json object to search
 * @param name the name of the member to be returned
 * @return a pointer to the json object, or NULL it the named
 *         member is not a json object.
 */
json* json_get_member_object(json* json, const char* name )
{
    json_value* p;
    
    p = (json_value*) apr_hash_get(json->elements, name, strlen(name));
    if( p == NULL ) return NULL;
    if( p->type != json_object ) return NULL;
    
    return p->value;
}


/**
 * Return whether or not the named json member exists.
 * @param json the json object to search
 * @param name the name of the member to test
 * @return true if the named member exists, false otherwise
 */
int json_has_member(json* json, const char* name )
{
    if( apr_hash_get(json->elements, name, strlen(name)) == NULL )
        return 0;
    else
        return 1;
}



/************************************
 * Internal methods
 ************************************/


/**
 * Reads a quoted string from a text stream.
 * @param start a pointer to the first character after the
 *        strating double quote.
 * @param end returns a pointer to the double quote at the end
 *        of the quoted string.
 * @return true if if found a complete string, false otherwise
 */
static int json_read_string( const char* start, const char** end )
{
    int escape = 0;
    const char* p = start;
    
    while(1)
    {
        if( *p == '\0') return !OK;
        if( *p == '"' && !escape ) break;
        if( escape )
            escape = 0;
        else if( *p == '\\' )
            escape = 1;

        ++p;
    }
    
    *end = p;
    return OK;
}



/**
 * Reads a number from a text stream.
 * @param start a pointer to the first character of the number
 * @param end returns a pointer to the first character after the
 *        number
 * @return true if if found a number, false otherwise
 */
static int json_read_number( const char* start, const char** end )
{
    char*   end_of_number;
    long    l;
    double  d;
    
    
    /*
     * First, try converting it as an integer. If this is successful,
     * we expect the following character to be whitespace, comma, or 
     * end-brace (according to the JSON grammar).
     */
    l = strtol(start, &end_of_number, 0 );
    if( strchr(" \t\r\n\f\v,}", *end_of_number) == NULL )
    {
        /* Try treating it as a decimal instead */
        
        d = strtod(start, &end_of_number);
    }
    
    if( strchr(" \t\r\n\f\v,}", *end_of_number) == NULL ) return !OK;
    
    *end = end_of_number;
    
    return OK;
}




/**
 * Reads a json array from a text stream.
 * @param pool a pool from which to allocate json objects
 * @param start a pointer to the first character after the array start '['
 * @param end returns a pointer to end of the array ']'
 * @return a pointer to a json array value, or NULL if the array could
 *         not be parsed.
 */
static json_value* json_read_array( apr_pool_t* pool, const char* start, const char** end )
{
    const char*         p = start;
    apr_array_header_t* list;
    int                 i;
    
    
    
    list = apr_array_make(pool, 100, sizeof(json_value));


    /*
     * Start parsing values
     */
    while( *p != ']' )
    {
        const char* value_start = p;
        const char* value_end;

        json_value* json_val = apr_array_push(list);
        
        
        if( !json_read_value(pool, json_val, value_start, &value_end) ) return NULL;
        p = value_end;
           
        while( apr_isspace(*p) ) ++p;  /* Skip white space preceding end of member */
        if( *p == '\0' ) return NULL;
        if( *p == ',' ) ++p;  /* Another value is expected to follow */       
    }
    
    *end = p;
    
    /*
     * Convert the apr array into a regular C array (makes it much
     * easier to deal with).
     */
    json_value* json_array;
    
    json_array = apr_pcalloc(pool, sizeof(json_value) * list->nelts);
    for( i = 0; i < list->nelts; ++i )
    {
        json_array[i] = ((json_value*)list->elts)[i];
    }
     
    return json_array;
}


/**
 * Reads a json object from a text stream.
 * @param pool a pool from which to allocate json objects
 * @param start a pointer to the start of the object ('{', or the
 *        white space preceeding it).
 * @param end returns a pointer to end of the object '}'
 * @return a pointer to a json object value, or NULL if the object could
 *         not be parsed.
 */
static json* json_parse_object( apr_pool_t* pool, const char* start, const char** end )
{
    const char*  p = start;
    json*        object = apr_pcalloc(pool, sizeof(*object));

    object->elements = apr_hash_make(pool);


    /*
     * Find the start of the object
     */   
    while( apr_isspace(*p) ) ++p;  /* Skip white space preceding object*/
    if( *p++ != '{' ) return NULL;
    

    /*
     * Start parsing members
     */
    while( *p != '}' )
    {
        const char* name_start;
        const char* name_end;
        const char* value_start;
        const char* value_end;

        json_value* json_val = apr_pcalloc(pool, sizeof(*json_val));
        
        
        while( apr_isspace(*p) ) ++p;  /* Skip white space preceding member name */
        if( *p++ != '"' ) return NULL;
       
        
        /*
         * Found start of member name. Now scan for end. We do not handle embedded
         * double quotes in the name at this point.
         */
        name_start = p;
        while( *p != '"' )
        {
            if( *p++ == '\0' ) return NULL;
        }
        name_end = p;
        ++p;
        
        while( apr_isspace(*p) ) ++p;  /* Skip white space preceding ':' */
        if( *p++ != ':' ) return NULL;
        
        value_start = p;
        if( !json_read_value(pool, json_val, value_start, &value_end) ) return NULL;
        p = value_end;


        apr_hash_set(object->elements,
            apr_pstrndup(pool, name_start, (name_end - name_start)),
            (name_end - name_start),
            json_val );

            
        while( apr_isspace(*p) ) ++p;  /* Skip white space preceding end of member */
        if( *p == '\0' ) return NULL;
        if( *p == ',' ) ++p;  /* Another member is expected to follow */       

    }
    
    *end = p;
    
    return object;
}



/**
 * Reads a generic json value from a text stream.
 * @param pool the pool from which to allocate objects
 * @param json_val the json value object to populate
 * @param start a pointer to the start of the value
 * @param end returns a pointer to the first charcter after the end of
 *        the value
 * @return true if a value was read succesfully, false otherwise.
 */
static int json_read_value( apr_pool_t* pool, json_value* json_val, const char* start, const char** end )
{
    const char*         p = start;


    const char* value_start;
    const char* value_end;

    while( apr_isspace(*p) ) ++p;  /* Skip white space preceding value */
       
    if( *p == '"' )
    {
        value_start = p + 1;
        if( json_read_string( value_start, &value_end ) != OK ) return 0;
        p = value_end + 1;
        
        json_val->type = json_string;
        json_val->value = apr_pstrndup(pool, value_start, (value_end - value_start));
    }
    else if( *p == '-' || apr_isdigit(*p) )
    {
        value_start = p;
        if( json_read_number( value_start, &value_end ) != OK ) return 0;
        p = value_end;
        json_val->type = json_number;
        json_val->value = apr_pstrndup(pool, value_start, (value_end - value_start));
    }
    else if( *p == 't' && strncmp(p, "true", 4) == 0 )
    {
        json_val->type = json_boolean;
        json_val->value = "true";

    	p += 4;
    }
    else if( *p == 'f' && strncmp(p, "false", 5) == 0 )
    {
        json_val->type = json_boolean;
        json_val->value = "false";

    	p += 5;
    }
    else if( *p == 'n' && strncmp(p, "null", 4) == 0 )
    {
        json_val->type = json_null;
        json_val->value = NULL;

    	p += 4;
    }
    else if( *p == '{' )
    {
        /*
         * We have encountered a child object. We handle this
         * with recursion.
         */
        json* child = json_parse_object(pool, p, &value_end);
        if( child == NULL ) return 0;
        
        json_val->type = json_object;
        json_val->value = child;
        p = value_end + 1;
    }
    else if( *p == '[' )
    {
        void* array;
        
        value_start = p + 1;
        array = json_read_array( pool, value_start, &value_end );
        if( array == NULL ) return 0;
        p = value_end + 1;
        
        json_val->type = json_array;
        json_val->value = array;
    }
    else
    {
        return 0;
    }

    *end = p;
    
    return 1;
}




/** JSON grammar


object
    {}
    { members } 
members
    pair
    pair , members
pair
    string : value
array
    []
    [ elements ]
elements
    value
    value , elements
value
    string
    number
    object
    array
    true
    false
    null

string
    ""
    " chars "
chars
    char
    char chars
char
    any-Unicode-character-
        except-"-or-\-or-
        control-character
    \"
    \\
    \/
    \b
    \f
    \n
    \r
    \t
    \u four-hex-digits 
number
    int
    int frac
    int exp
    int frac exp 
int
    digit
    digit1-9 digits
    - digit
    - digit1-9 digits 
frac
    . digits
exp
    e digits
digits
    digit
    digit digits
e
    e
    e+
    e-
    E
    E+
    E-


**/
