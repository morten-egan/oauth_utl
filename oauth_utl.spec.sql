create or replace package oauth_utl

as

	/** This is a plsql package for oauth requests
	* @author Morten Egan
	* @version 0.0.1
	* @project oauth_utl
	*/
	p_version						varchar2(50) 		:= '0.0.1';
	oauth_signature_method			varchar2(50) 		:= utl_url.escape('HMAC-SHA1');
	oauth_version					varchar2(10)		:= utl_url.escape('1.0');

end oauth_utl;
/