create or replace package oauth_utl

as

	/** This is a plsql package for oauth requests
	* @author Morten Egan
	* @version 0.0.1
	* @project oauth_utl
	*/
	p_version						varchar2(50) 		:= '0.0.1';
	type param_arr is table of varchar2(4000) index by varchar2(4000);

	/** Set Oauth general settings here
	* @author Morten Egan
	* @param oauth_version What version of Oauth to use. Currently only 1.0 supported.
	*/
	procedure oauth_setup (
		oauth_version						in				varchar2 default '1.0'
		, oauth_signature_type				in				varchar2 default 'HMAC-SHA1'
		, oauth_callback					in				varchar2 default 'oob'
	);

	/** Setup the client key and secret for the Oauth session
	* @author Morten Egan
	* @param client_key The client key
	* @param client_secret The client secret
	*/
	procedure oauth_client_setup (
		client_key						in				varchar2
		, client_secret					in				varchar2
	);

	/** Oauth get temporary credentials
	* @author Morten Egan
	*/
	procedure oauth_request_token;

end oauth_utl;
/