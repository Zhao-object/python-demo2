import requests

class FlaskAPITester:
    """Flask 接口测试类（支持用户、商品、订单模块）"""
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url
        self.session = requests.Session()  # 持久会话，提升效率
        self.session.headers.update({"Content-Type": "application/json"})  # 默认 JSON 格式

    def _request(self, method, endpoint, json=None, params=None):
        """通用请求方法（封装异常处理）"""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        try:
            response = self.session.request(
                method=method,
                url=url,
                json=json,
                params=params,
                timeout=10  # 超时保护
            )
            response.raise_for_status()  # 自动抛出 HTTP 错误（4xx/5xx）
            return response.json()       # 解析 JSON 响应
        except requests.RequestException as e:
            # 捕获所有请求异常，返回错误详情
            error_info = {"error": str(e)}
            if hasattr(e, "response") and e.response:
                error_info["status_code"] = e.response.status_code
                try:
                    error_info.update(e.response.json())
                except:
                    error_info["raw_response"] = e.response.text
            return error_info

    # ====================== 用户接口 ======================
    def create_user(self, data):
        """创建用户（必填：phone, id_card, name）"""
        return self._request("POST", "api/users", json=data)

    def get_user(self, user_id = 1):
        """查询用户详情"""
        return self._request("GET", f"api/users/{user_id}")

    # ====================== 商品接口 ======================
    def create_product(self, data):
        """创建商品（必填：code, title, category_id）"""
        return self._request("POST", "api/products", json=data)

    def list_products(self, status=None):
        """查询商品列表（可选：status 筛选）"""
        params = {"status": status} if status else {}
        return self._request("GET", "api/products", params=params)

    # ====================== 订单接口 ======================
    def create_order(self, data):
        """创建订单（必填：order_no, user_id, product_id）"""
        return self._request("POST", "api/orders", json=data)

    def get_order_detail(self, order_id):
        """查询订单详情（含用户、商品关联数据）"""
        return self._request("GET", f"api/orders/{order_id}")


# -------------------- 测试用例（直接运行即可） --------------------
if __name__ == "__main__":
    tester = FlaskAPITester()

    # 1. 创建测试用户
    user_data = {
        "phone": "13800131240",
        "id_card": "14010519491231002X",
        "name": "苍天已死"
    }
    user_res = tester.create_user(user_data)
    print("\n=== 创建用户响应 ===")
    print(user_res)
    user_id = user_res.get("data", {}).get("user_id")

    # 1. 查询用户

    user_res_query = tester.get_user()
    print("\n=== 创建用户响应 ===")
    print(user_res_query)
    user_id = user_res_query.get("data", {}).get("user_id")

    # # 2. 创建测试商品
    # product_data = {
    #     "code": "TEST001",
    #     "title": "测试商品",
    #     "category_id": "0101"
    # }
    # product_res = tester.create_product(product_data)
    # print("\n=== 创建商品响应 ===")
    # print(product_res)
    # product_id = product_res.get("data", {}).get("product_id")
    #
    # # 3. 创建测试订单（依赖用户和商品 ID）
    # if user_id and product_id:
    #     order_data = {
    #         "order_no": "ORDER_20250825_001",
    #         "user_id": user_id,
    #         "product_id": product_id
    #     }
    #     order_res = tester.create_order(order_data)
    #     print("\n=== 创建订单响应 ===")
    #     print(order_res)
    #     order_id = order_res.get("data", {}).get("order_id")
    #
    #     # 4. 查询订单详情（验证关联数据）
    #     if order_id:
    #         order_detail = tester.get_order_detail(order_id)
    #         print("\n=== 订单详情响应 ===")
    #         print(order_detail)
    # else:
    #     print("\n⚠️ 用户或商品创建失败，跳过订单测试")

    #这是一次新的git版本！！！！！