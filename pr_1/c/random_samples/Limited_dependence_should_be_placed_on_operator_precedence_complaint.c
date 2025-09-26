
x = a + b;
x = a * -1;
x = a + b + c;
x = f ( a + b, c );

x = ( a == b ) ? a : ( a - b );
x = ( a + b ) - ( c + d );
x = ( a * 3 ) + c + d;
// {fact rule=precedence-logic-error@v1.0 defects=0}
if ( (a = f(b,c)) == true) { ... }
(x - b) ? a : c; // Compliant
// {/fact}
// {fact rule=precedence-logic-error@v1.0 defects=0}
(s &lt;&lt; 5) == 1; // Compliant
// {/fact}
