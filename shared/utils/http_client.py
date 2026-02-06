"""
HTTP client for inter-service communication
"""
import httpx
import json
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


class ServiceClient:
    """HTTP client for calling other microservices"""
    
    def __init__(self, base_url: str, timeout: int = 30):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout)
    
    async def get(
        self,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """GET request"""
        url = f"{self.base_url}{path}"
        try:
            response = await self.client.get(url, headers=headers, params=params)
            response.raise_for_status()
            # Handle empty responses
            if not response.content:
                logger.warning(f"Empty response from {url}")
                return {}
            # Try to parse JSON, raise error if parsing fails (so caller can handle it)
            try:
                return response.json()
            except (ValueError, json.JSONDecodeError) as e:
                logger.error(f"Failed to parse JSON response from {url}: {e}, response text: {response.text[:200]}")
                raise httpx.DecodingError(f"Failed to decode JSON response from {url}: {e}", request=response.request, response=response) from e
        except httpx.HTTPError as e:
            logger.error(f"GET {url} failed: {e}")
            raise
    
    async def post(
        self,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        content: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """POST request"""
        url = f"{self.base_url}{path}"
        try:
            # If content (raw bytes) is provided, use it directly
            if content is not None:
                response = await self.client.post(url, content=content, headers=headers)
            else:
                response = await self.client.post(url, data=data, json=json, headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"POST {url} failed: {e}")
            raise
    
    async def put(
        self,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        content: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """PUT request"""
        url = f"{self.base_url}{path}"
        try:
            # If content (raw bytes) is provided, use it directly
            if content is not None:
                response = await self.client.put(url, content=content, headers=headers)
            else:
                response = await self.client.put(url, data=data, json=json, headers=headers)
            response.raise_for_status()
            # Handle empty responses
            if not response.content:
                logger.warning(f"Empty response from {url}")
                return {}
            # For 204 No Content, return empty dict
            if response.status_code == 204:
                return {}
            # Try to parse JSON, handle parsing errors gracefully
            try:
                return response.json()
            except (ValueError, json.JSONDecodeError) as e:
                logger.error(f"Failed to parse JSON response from {url}: {e}, response text: {response.text[:200]}")
                # Return empty dict instead of raising error
                return {}
        except httpx.HTTPError as e:
            logger.error(f"PUT {url} failed: {e}")
            raise
    
    async def patch(
        self,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """PATCH request"""
        url = f"{self.base_url}{path}"
        try:
            response = await self.client.patch(url, data=data, json=json, headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"PATCH {url} failed: {e}")
            raise
    
    async def delete(
        self,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Optional[Dict[str, Any]]:
        """DELETE request with JSON body support"""
        url = f"{self.base_url}{path}"
        try:
            request_json = json if json is not None else data

            if request_json is not None:
                # httpx.delete() doesn't accept json/content in some versions
                # Use request() method for full control
                import json as json_module
                request_headers = headers or {}
                request_headers["Content-Type"] = "application/json"

                response = await self.client.request(
                    method="DELETE",
                    url=url,
                    content=json_module.dumps(request_json),
                    headers=request_headers
                )
            else:
                # No body, use standard delete
                response = await self.client.delete(url, headers=headers)

            response.raise_for_status()

            # For 204 No Content, return None instead of trying to parse JSON
            if response.status_code == 204:
                return None
            # For other status codes, try to parse JSON if content exists
            if response.content:
                try:
                    return response.json()
                except:
                    return {}
            return {}
        except httpx.HTTPError as e:
            logger.error(f"DELETE {url} failed: {e}")
            raise
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()

