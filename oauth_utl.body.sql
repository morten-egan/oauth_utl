set scan off;
create or replace package body oauth_utl

as

	/** Valid switch values:
	* REQUEST_TOKEN - The very first call to get the temporary credentials
	* ACCESS_TOKEN - Get the access tokens for the resource, with verified and authorized request token
	* RESOURCE - Make a resoure request, with verified and authorized Oauth tokens
	*/
	generate_switch					varchar2(50)			:= 'REQUEST_TOKEN';
	oauth_parameters				oauth_utl.param_arr;

	-- Oauth basic settings
	oauth_signature_sha1			raw(2000)				:= null;

	-- Endpoints
	oauth_authorize_url				varchar2(4000)			:= null;

	-- HTTP Types
	oauth_request					utl_http.req;
	oauth_response					utl_http.resp;
	oauth_header_name				varchar2(4000);
	oauth_header_val				varchar2(4000);
	oauth_body_line					varchar2(4000);

	procedure oauth_defaults
	
	as
	
	begin
	
		dbms_application_info.set_action('oauth_defaults');

		oauth_parameters('oauth_http_method') := 'POST';
		oauth_parameters('oauth_callback') := 'oob';
		oauth_parameters('oauth_callback_url') := null;
	
		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;
	
	end oauth_defaults;

	function real_url_encode (
		str_in						in				varchar2
	)
	return varchar2
	
	as
	
		l_ret_val			varchar2(4000);
		l_bad   			varchar2(100) default ' >%}\~];?@&<#{|^[`/:=$+''"';  
    	l_char  			char(1);  
	
	begin
	
		dbms_application_info.set_action('real_url_encode');

		for i in 1 .. nvl(length(str_in),0) loop  
			l_char :=  substr(str_in,i,1);  
			if ( instr( l_bad, l_char ) > 0 ) then  
				l_ret_val := l_ret_val || '%' ||  to_char( ascii(l_char), 'fmXX' );  
			else  
				l_ret_val := l_ret_val || l_char;  
			end if;  
		end loop;
	
		dbms_application_info.set_action(null);
	
		return l_ret_val;
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;
	
	end real_url_encode;

	procedure assert_supported
	
	as

		oauth_exc						exception;
		pragma							exception_init(oauth_exc, -20001);
	
	begin
	
		dbms_application_info.set_action('assert_supported');

		if oauth_parameters('oauth_version') is not null and oauth_parameters('oauth_version') != real_url_encode('1.0') then
			raise_application_error(-20001, 'Only Oauth version 1.0 is currently supported.');
		end if;

		if oauth_parameters('oauth_signature_method') is not null and oauth_parameters('oauth_signature_method') != real_url_encode('HMAC-SHA1') then
			raise_application_error(-20001, 'Only HMAC-SHA1 signatures is currently supported.');
		end if;
	
		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;
	
	end assert_supported;

	procedure generate_nonce

	as

	begin

		assert_supported;

		oauth_parameters('oauth_nonce') := dbms_random.string('A', 15);
		oauth_parameters('oauth_nonce') := real_url_encode(utl_encode.base64_encode(utl_i18n.string_to_raw (oauth_parameters('oauth_nonce'), 'AL32UTF8')));

	end generate_nonce;

	procedure generate_timestamp

	as

	begin

		dbms_application_info.set_action('generate_timestamp');

		assert_supported;

		oauth_parameters('oauth_timestamp') := real_url_encode(round(((sysdate - to_date('01-01-1970', 'DD-MM-YYYY'))  * (86400)) - 7200));

		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;

	end generate_timestamp;

	procedure generate_base
	
	as
	
	begin
	
		dbms_application_info.set_action('generate_base');

		assert_supported;

		if generate_switch = 'REQUEST_TOKEN' then
			oauth_parameters('oauth_base_string') := 	oauth_parameters('oauth_http_method')
									|| '&'
									|| real_url_encode(oauth_parameters('oauth_request_token_url'))
									|| '&'
									|| real_url_encode(
										'oauth_callback='
										|| oauth_parameters('oauth_callback')
										|| '&oauth_consumer_key='
										|| oauth_parameters('oauth_consumer_key')
										|| '&oauth_nonce='
										|| oauth_parameters('oauth_nonce')
										|| '&oauth_signature_method='
										|| oauth_parameters('oauth_signature_method')
										|| '&oauth_timestamp='
										|| oauth_parameters('oauth_timestamp')
										|| '&oauth_version='
										|| oauth_parameters('oauth_version')
									);
		elsif generate_switch = 'ACCESS_TOKEN' then
			oauth_parameters('oauth_base_string') := 	oauth_parameters('oauth_http_method')
									|| '&'
									|| real_url_encode(oauth_parameters('oauth_access_token_url'))
									|| '&'
									|| real_url_encode(
										'oauth_consumer_key='
										|| oauth_parameters('oauth_consumer_key')
										|| '&oauth_nonce='
										|| oauth_parameters('oauth_nonce')
										|| '&oauth_signature_method='
										|| oauth_parameters('oauth_signature_method')
										|| '&oauth_timestamp='
										|| oauth_parameters('oauth_timestamp')
										|| '&oauth_token='
										|| oauth_parameters('oauth_request_key')
										|| '&oauth_verifier='
										|| oauth_parameters('oauth_authorize_verifier')
										|| '&oauth_version='
										|| oauth_parameters('oauth_version')
									);
		elsif generate_switch = 'RESOURCE' then
			oauth_parameters('oauth_base_string') := 	oauth_parameters('oauth_http_method')
									|| '&'
									|| real_url_encode(oauth_parameters('oauth_resource_url'))
									|| '&'
									|| real_url_encode(
										'oauth_consumer_key='
										|| oauth_parameters('oauth_consumer_key')
										|| '&oauth_nonce='
										|| oauth_parameters('oauth_nonce')
										|| '&oauth_signature_method='
										|| oauth_parameters('oauth_signature_method')
										|| '&oauth_timestamp='
										|| oauth_parameters('oauth_timestamp')
										|| '&oauth_token='
										|| oauth_parameters('oauth_access_key')
										|| '&oauth_version='
										|| oauth_parameters('oauth_version')
										-- Here we add other custom inputs if any
									);
		end if;
		
		dbms_output.put_line(oauth_parameters('oauth_base_string'));
	
		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;
	
	end generate_base;

	procedure generate_signature
	
	as
	
	begin
	
		dbms_application_info.set_action('generate_signature');

		assert_supported;

		oauth_signature_sha1 := dbms_crypto.mac (
									src 	=> utl_i18n.string_to_raw (oauth_parameters('oauth_base_string'), 'AL32UTF8'),
                                	typ		=> dbms_crypto.hmac_sh1,
                                	key		=> utl_i18n.string_to_raw (oauth_parameters('oauth_key'), 'AL32UTF8')
                            	);

		oauth_parameters('oauth_signature_sha1_base64') := utl_raw.cast_to_varchar2(utl_encode.base64_encode(oauth_signature_sha1));

		dbms_output.put_line('Base64 Signature: ' || oauth_parameters('oauth_signature_sha1_base64'));
	
		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;
	
	end generate_signature;

	procedure generate_request_token_url
	
	as
	
	begin
	
		dbms_application_info.set_action('generate_request_token_url');

		assert_supported;

		if generate_switch = 'REQUEST_TOKEN' then
			oauth_parameters('oauth_request_url') := 	oauth_parameters('oauth_request_token_url')
								|| '?oauth_callback='
								|| oauth_parameters('oauth_callback')
								|| '&oauth_consumer_key='
								|| oauth_parameters('oauth_consumer_key')
								|| '&oauth_nonce='
								|| oauth_parameters('oauth_nonce')
								|| '&oauth_signature='
								|| real_url_encode(oauth_parameters('oauth_signature_sha1_base64'))
								|| '&oauth_signature_method='
								|| oauth_parameters('oauth_signature_method')
								|| '&oauth_timestamp='
								|| oauth_parameters('oauth_timestamp')
								|| '&oauth_version='
								|| oauth_parameters('oauth_version');
		elsif generate_switch = 'ACCESS_TOKEN' then
			oauth_parameters('oauth_request_url') := 	oauth_parameters('oauth_access_token_url')
								|| '?oauth_consumer_key='
								|| oauth_parameters('oauth_consumer_key')
								|| '&oauth_nonce='
								|| oauth_parameters('oauth_nonce')
								|| '&oauth_signature_method='
								|| oauth_parameters('oauth_signature_method')
								|| '&oauth_timestamp='
								|| oauth_parameters('oauth_timestamp')
								|| '&oauth_token='
								|| oauth_parameters('oauth_request_key')
								|| '&oauth_verifier='
								|| oauth_parameters('oauth_authorize_verifier')
								|| '&oauth_version='
								|| oauth_parameters('oauth_version');
		elsif generate_switch = 'RESOURCE' then
			oauth_parameters('oauth_request_url') := 	oauth_parameters('oauth_resource_url');
								-- || '?oauth_callback='
								-- Add any custom vars if required
		end if;

		dbms_output.put_line('Full request token url: ' || oauth_parameters('oauth_request_url'));
	
		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;
	
	end generate_request_token_url;

	procedure generate_oauth_header
	
	as
	
	begin
	
		dbms_application_info.set_action('generate_oauth_header');

		assert_supported;

		if generate_switch = 'REQUEST_TOKEN' then
			oauth_parameters('oauth_header') := 	'Authorization: OAuth oauth_nonce="' || oauth_parameters('oauth_nonce') || '", '
							|| 'oauth_callback="' || oauth_parameters('oauth_callback') ||'", '
							|| 'oauth_signature_method="'|| oauth_parameters('oauth_signature_method') || '", '
							|| 'oauth_timestamp="'|| oauth_parameters('oauth_timestamp') || '", '
							|| 'oauth_consumer_key="'|| oauth_parameters('oauth_consumer_key') || '", '
							|| 'oauth_signature="' || real_url_encode(oauth_parameters('oauth_signature_sha1_base64')) || '", '
							|| 'oauth_version="' || oauth_parameters('oauth_version') || '"';
		elsif generate_switch = 'ACCESS_TOKEN' then
			oauth_parameters('oauth_header') := 	'Authorization: OAuth oauth_nonce="' || oauth_parameters('oauth_nonce') || '", '
							|| 'oauth_signature_method="'|| oauth_parameters('oauth_signature_method') || '", '
							|| 'oauth_timestamp="'|| oauth_parameters('oauth_timestamp') || '", '
							|| 'oauth_consumer_key="'|| oauth_parameters('oauth_consumer_key') || '", '
							|| 'oauth_token="'|| oauth_parameters('oauth_request_key') || '", '
							|| 'oauth_verifier="'|| oauth_parameters('oauth_authorize_verifier') || '", '
							|| 'oauth_signature="' || real_url_encode(oauth_parameters('oauth_signature_sha1_base64')) || '", '
							|| 'oauth_version="' || oauth_parameters('oauth_version') || '"';
		elsif generate_switch = 'RESOURCE' then
			oauth_parameters('oauth_header') := 	'Authorization: OAuth oauth_nonce="' || oauth_parameters('oauth_nonce') || '", '
							|| 'oauth_signature_method="'|| oauth_parameters('oauth_signature_method') || '", '
							|| 'oauth_timestamp="'|| oauth_parameters('oauth_timestamp') || '", '
							|| 'oauth_consumer_key="'|| oauth_parameters('oauth_consumer_key') || '", '
							|| 'oauth_token="'|| oauth_parameters('oauth_access_key') || '", '
							|| 'oauth_signature="' || real_url_encode(oauth_parameters('oauth_signature_sha1_base64')) || '", '
							|| 'oauth_version="' || oauth_parameters('oauth_version') || '"';
		end if;

		dbms_output.put_line('Oauth header: ' || oauth_parameters('oauth_header'));
	
		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;
	
	end generate_oauth_header;

	procedure generate_key
	
	as
	
	begin
	
		dbms_application_info.set_action('generate_key');

		assert_supported;

		if generate_switch = 'REQUEST_TOKEN' then
			oauth_parameters('oauth_key') := oauth_parameters('oauth_consumer_secret') || '&';
		elsif generate_switch = 'ACCESS_TOKEN' then
			oauth_parameters('oauth_key') := oauth_parameters('oauth_consumer_secret') || '&' || oauth_parameters('oauth_request_secret');
		elsif generate_switch = 'RESOURCE' then
			oauth_parameters('oauth_key') := oauth_parameters('oauth_consumer_secret') || '&' || oauth_parameters('oauth_access_secret');
		end if;
	
		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;
	
	end generate_key;

	procedure send_request
	
	as
	
	begin
	
		dbms_application_info.set_action('send_request');

		assert_supported;

		-- Extended error checking
		utl_http.set_response_error_check(
			enable => true
		);
		utl_http.set_detailed_excp_support(
			enable => true
		);

		oauth_request := utl_http.begin_request (
			url		=>	oauth_parameters('oauth_request_url'),
			method	=>	oauth_parameters('oauth_http_method')
		);

		utl_http.set_header (
			r		=>	oauth_request,
			name	=>	'Authorization',
			value	=>	oauth_parameters('oauth_header')
		);

		utl_http.write_text (
			r		=>	oauth_request,
			data	=>	''
		);

		-- Now we can get the output and parse it.
		oauth_response := utl_http.get_response (
			r		=>	oauth_request
		);

		-- Header parse
		for i in 1..utl_http.get_header_count(oauth_response) loop
			utl_http.get_header (
				r => oauth_response
				, n => i
				, name => oauth_header_name
				, value => oauth_header_val
			);
			dbms_output.put_line(oauth_header_name || ': ' || oauth_header_val);
		end loop;

		-- Content parse
		begin
			loop
				utl_http.read_line (
					r			=>	oauth_response,
					data		=>	oauth_body_line,
					remove_crlf	=>	true
				);
				dbms_output.put_line(oauth_body_line);
			end loop;

			exception
				when utl_http.end_of_body then
					null;
		end;

		utl_http.end_response(
			r 		=>	oauth_response
		);
	
		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				dbms_output.put_line('HTTP ERROR: ' || utl_http.get_detailed_sqlerrm);
				utl_http.end_response(
					r 		=>	oauth_response
				);
	
	end send_request;

	procedure oauth_setup (
		oauth_version						in				varchar2 default '1.0'
		, oauth_signature_type				in				varchar2 default 'HMAC-SHA1'
		, oauth_callback					in				varchar2 default 'oob'
	)
	
	as
	
	begin
	
		dbms_application_info.set_action('oauth_setup');

		oauth_parameters('oauth_signature_method') := real_url_encode(oauth_signature_type);
		oauth_parameters('oauth_version') := real_url_encode(oauth_version);
		oauth_parameters('oauth_callback') := oauth_callback;
	
		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;
	
	end oauth_setup;

	procedure oauth_client_setup (
		client_key						in				varchar2
		, client_secret					in				varchar2
	)
	
	as
	
	begin
	
		dbms_application_info.set_action('oauth_client_setup');

		-- Setting parms
		oauth_parameters('oauth_consumer_key') := client_key;
		oauth_parameters('oauth_consumer_secret') := client_secret;
	
		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;
	
	end oauth_client_setup;

	procedure oauth_request_token
	
	as

		oauth_exc						exception;
		pragma							exception_init(oauth_exc, -20001);

	
	begin
	
		dbms_application_info.set_action('oauth_request_token');

		if oauth_parameters('oauth_signature_method') is null and oauth_parameters('oauth_version') is null and oauth_parameters('oauth_callback') is null then
			-- Oauth setup has not been called, run with default
			oauth_setup;
		end if;

		generate_switch := 'REQUEST_TOKEN';

		if oauth_parameters('oauth_consumer_key') is null or oauth_parameters('oauth_consumer_secret') is null then
			raise_application_error(-20001, 'Client key or secret not defined. Please use oauth_client_setup.');
		end if;

		generate_nonce;
		generate_timestamp;
		generate_base;
		generate_key;
		generate_signature;
		generate_request_token_url;
		generate_oauth_header;
		send_request;
	
		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;
	
	end oauth_request_token;

	procedure oauth_access_token
	
	as

		oauth_exc						exception;
		pragma							exception_init(oauth_exc, -20001);
	
	begin
	
		dbms_application_info.set_action('oauth_access_token');

		if oauth_parameters('oauth_signature_method') is null and oauth_parameters('oauth_version') is null then
			-- Oauth setup has not been called, run with default
			oauth_setup;
		end if;

		if oauth_parameters('oauth_consumer_key') is null or oauth_parameters('oauth_consumer_secret') is null then
			raise_application_error(-20001, 'Client key or secret not defined. Please use oauth_client_setup.');
		end if;

		if oauth_parameters('oauth_request_key') is null or oauth_parameters('oauth_request_secret') is null then
			raise_application_error(-20001, 'Request key or secret not defined. Please use oauth_request_setup.');
		end if;

		generate_switch := 'ACCESS_TOKEN';

		generate_nonce;
		generate_timestamp;
		generate_base;
		generate_key;
		generate_signature;
		generate_request_token_url;
		generate_oauth_header;
		send_request;
	
		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;
	
	end oauth_access_token;

begin

	oauth_defaults;
	dbms_application_info.set_client_info('oauth_utl');
	dbms_session.set_identifier('oauth_utl');

end oauth_utl;
/