@ignore
Feature: JWKS endpoint

	Background:
  	* def mainUrl = jwksUrl

  Scenario: Retrieve JWKS
    Given url  mainUrl
    And header Authorization = 'Bearer ' + accessToken
    When method GET
    Then status 200
    And print response
    And assert response.length != null
    
  Scenario: Post JWKS
    Given url  mainUrl
    And header Authorization = 'Bearer ' + accessToken
    And request read('csr.json')
    And print request
    When method POST
    Then status 200
    And print response
    And assert response.length != null
    
  @ignore  
    Scenario: Post JWKS
    Given url  mainUrl
    And header Authorization = 'Bearer ' + accessToken
    When method GET
    Then status 200
    Then print response
    Then def first_response = response 
    Given url  mainUrl
    And header Authorization = 'Bearer ' + accessToken
    And request first_response 
    When method POST
    Then status 200
    And print response
    And assert response.length != null
    
@ignore
  Scenario: Import JWKS
    Given url  mainUrl
    And header Authorization = 'Bearer ' + accessToken
    And request read('jwk-post.json')
    When method POST
    Then status 200
    And print response
    And assert response.length != null

@ignore
   Scenario: Patch JWKS with new key
    Given url  mainUrl
    And header Authorization = 'Bearer ' + accessToken
    When method GET
    Then status 200
    And print response
    And assert response.length != null
  	Given url  mainUrl
    And header Authorization = 'Bearer ' + accessToken
    And header Content-Type = 'application/json-patch+json'
    And header Accept = 'application/json'
    And print response.keys[0].exp
    And request "[ {\"op\":\"replace\", \"path\": \"/keys/0/exp\", \"value\":\""+response.keys[0].exp+"\" } ]"
	Then print request
    When method PATCH
    Then status 200
    And print response

@ignore
  Scenario: Put JWKS
    Given url  mainUrl
    And header Authorization = 'Bearer ' + accessToken
    When method GET
    Then status 200
    Then print response
    Then def first_response = response 
    Given url  mainUrl
    And header Authorization = 'Bearer ' + accessToken
    And request first_response 
    When method PUT
    Then status 200
    And print response
    And assert response.length != null
