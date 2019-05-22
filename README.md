Get access token & refresh token from Keycloak:

curl --request POST \
  --url http://localhost:8080/auth/realms/demo-realm/protocol/openid-connect/token \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data 'grant_type=password&client_id=spring-boot&client_secret=2265ebb8-fe76-4a75-ab8b-b4b5a9738aa8&username=hugo.hase&password=hugo1'
  
  
Call service:
curl --request GET \
  --url http://localhost:8081/secret/hello \
  --header 'authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUeTdxazZvdDJ6LWZsZXVUTmNFNGIyXzctdGZkazdwc3Vkb3R6d3IzYmJBIn0.eyJqdGkiOiIyODFiNTE3My04MmMzLTQzNDQtYjk2YS1kMzE2ZDgwMDFjMzQiLCJleHAiOjE1NTQ0MTAwNzEsIm5iZiI6MCwiaWF0IjoxNTU0NDA5NzcxLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvZGVtby1yZWFsbSIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI0MzBjNTA1Yi00NTBmLTRkY2EtOWQ4Yi04ZWM2ZDQ5ODE3Y2MiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJzcHJpbmctYm9vdCIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6IjgxNzIxNTdmLWIyMTYtNDg5NC1iYzM4LTgxMTAxYTkyNjUyZiIsImFjciI6IjEiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7InNwcmluZy1ib290Ijp7InJvbGVzIjpbImFwcGxfdXNlcnMiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6Ikh1Z28gSGFzZSBIYXNlIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiaHVnby5oYXNlIiwiZ2l2ZW5fbmFtZSI6Ikh1Z28gSGFzZSIsImZhbWlseV9uYW1lIjoiSGFzZSIsImVtYWlsIjoiaHVnbzIuaGFzZUB0ZXN0LmNoIn0.RiszKHVqG1zJTOsFc6J-OqEp5T__Ev0Bs0Cig-NPlAQ9uusQ5ef1Tb3aoMmKRt150dPArNjsTyN8rOscCnlp0xJ9SIRQLsqdD3H-qe-waw0Knf-pWPRo63qvCnG4FRJuTCAFul8V11B3PyhqKk_zUUxL3oV3-jH5E_fnBZG8v1DhorSzdNFOE_HkY0ENfYB6DnXOYkUMqlWXwsdz30Z7-_AcLCL-Tmhof16s44vfdZrvbwdFDZzGm6DOUkx4kPD4oDOIM50qWwlNRP9yDwwjunRDieIxOLj5kPal_hOmb54_IKTwYrSByTe5IiaiLjXNDVcWxlFoRsSejQ1lL2f4bQ'
  

Get a new access token with the refresh token:
curl --request POST \
  --url http://localhost:8080/auth/realms/demo-realm/protocol/openid-connect/token \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data 'client_id=spring-boot&grant_type=refresh_token&refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIwZTMyNTUzOS0zNzc3LTQyZTgtYjRiYy04MWFiYWExZjk3NWEifQ.eyJqdGkiOiIxMzgzODVlYS00NzVlLTRlM2ItYTg5NC1jNGJkOGIwZWE3NDAiLCJleHAiOjE1NTQ0MDg4MDMsIm5iZiI6MCwiaWF0IjoxNTU0NDA3MDAzLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvZGVtby1yZWFsbSIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9hdXRoL3JlYWxtcy9kZW1vLXJlYWxtIiwic3ViIjoiNDMwYzUwNWItNDUwZi00ZGNhLTlkOGItOGVjNmQ0OTgxN2NjIiwidHlwIjoiUmVmcmVzaCIsImF6cCI6InNwcmluZy1ib290IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiMjFiMTE3MDYtMGJjMS00ZWE0LWJkZDQtNWIzZDA4NzliNDg0IiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJzcHJpbmctYm9vdCI6eyJyb2xlcyI6WyJhcHBsX3VzZXJzIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwifQ.ZxbwXzapAJQVOIUtbIWc2_ttHUNABnCebhmxf7zB_7o&client_secret=2265ebb8-fe76-4a75-ab8b-b4b5a9738aa8'