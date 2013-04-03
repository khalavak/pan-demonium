
# Class for defining Credit Card Branch information used for finding PANs

class CardBranch:

    def amex():
    
        description = "AMEX credit card numbers"
        info = "The detected files contain possible American Express credit card numbers - start with the numbers 34 or 37."
        cmd =  "/usr/bin/find /home /tmp -type f -print0 |/usr/bin/xargs -0 /bin/egrep -H -s '([^0-9a-zA-Z_-]|^)(3(4[0-9]{2}|7[0-9]{2})( |-|)[0-9]{6}( |-|)[0-9]{5})([^0-9a-zA-Z_-]|$)'| /bin/egrep '\:[^0]' || /bin/echo '0'"
        regexp = "([^0-9a-zA-Z_-]|^)(3(4[0-9]{2}|7[0-9]{2})( |-|)[0-9]{6}(|-|)[0-9]{5})([^0-9a-zA-Z_-]|$)"



    def discover():

        description = "Discover credit card numbers"
        info = "The detected files contain possible Discover credit card numbers -  start with 6011 and 65 and contain 16 digits."
        cmd = "/usr/bin/find /home /tmp -type f -print0 |/usr/bin/xargs -0 /bin/egrep -H -s '([^0-9a-zA-Z_-]|^)(6011( |-|)[0-9]{4}( |-|)[0-9]{4}( |-|)[0-9]{4})([^0-9a-zA-Z_-]|$)'| /bin/egrep '\:[^0]' || /bin/echo '0'"
        regexp_6011x = "([^0-9a-zA-Z_-]|^)(6011( |-|)[0-9]{4}( |-|)[0-9]{4}( |-|)[0-9]{4})([^0-9a-zA-Z_-]|$)"
        regexp_65x = "([^0-9a-zA-Z_-]|^)(65([0-9]{2}|-|)[0-9]{4}( |-|)[0-9]{4}( |-|)[0-9]{4})([^0-9a-zA-Z_-]|$)"



    def mastercard():
  
        description = "Mastercard credit card numbers"
        info = "The detected files contain possible MasterCard credit card numbers - start with the numbers 51 through 55 and contain 15 digits."
        cmd = "/usr/bin/find /home /tmp -type f -print0 |/usr/bin/xargs -0 /bin/egrep -H -s '([^0-9a-zA-Z_-]|^)(5[1-5][0-9]{2}( |-|)([0-9]{4})( |-|)([0-9]{4})( |-|)([0-9]{4}))([^0-9a-zA-Z_-]|$)'| /bin/egrep '\:[^0]' || /bin/echo '0'"
        regexp = "([^0-9a-zA-Z_-]|^)(5[1-5][0-9]{2}( |-|)([0-9]{4})( |-|)([0-9]{4})( |-|)([0-9]{4}))([^0-9a-zA-Z_-]|$)"



    def visa():

        description = "Visa credit card numbers"
        info = "The detected files contain possible Visa credit card numbers - start with the number four and contain 13 and 16 digits."
        cmd_13 = "/usr/bin/find /home /tmp -type f -print0 |/usr/bin/xargs -0 /bin/egrep -H -s '([^0-9a-zA-Z_-]|^)(4( |-|)([0-9]{4})( |-|)([0-9]{4})( |-|)([0-9]{4}))([^0-9a-zA-Z_-]|$)'| /bin/egrep '\:[^0]' || /bin/echo '0'"
        cmd_16 = "/usr/bin/find /home /tmp -type f -print0 |/usr/bin/xargs -0 /bin/egrep -H -s '([^0-9a-zA-Z_-]|^)(4[0-9]{3}( |-|)([0-9]{4})( |-|)([0-9]{4})( |-|)([0-9]{4}))([^0-9a-zA-Z_-]|$)'| /bin/egrep '\:[^0]' || /bin/echo '0'"

        regexp_13 = "([^0-9a-zA-Z_-]|^)(4( |-|)([0-9]{4})( |-|)([0-9]{4})( |-|)([0-9]{4}))([^0-9a-zA-Z_-]|$)"
        regexp_16 = "([^0-9a-zA-Z_-]|^)(4[0-9]{3}( |-|)([0-9]{4})( |-|)([0-9]{4})( |-|)([0-9]{4}))([^0-9a-zA-Z_-]|$)"



