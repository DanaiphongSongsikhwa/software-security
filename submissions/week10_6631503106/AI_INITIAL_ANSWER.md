# AI audit: complete initial candidate answer

Prompt: Give a minimal fix for the Week 10 BOLA endpoint, using the existing current_user helper.

AI-generated candidate (for review; incomplete):

Add authentication and an ownership check before returning orders:

```python
@app.get("/api/users/<int:uid>/orders")
def get_orders(uid):
    caller = current_user()
    if caller is None:
        return jsonify({"error": "authentication required"}), 401
    if caller["id"] != uid and not caller["is_admin"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(ORDERS.get(uid, []))
```

This blocks an unauthenticated caller and stops Alice, identified by X-User-Id: 1,
from reading Carol's orders. Test no header, Alice reading Carol, and Alice reading
Alice; the expected statuses are 401, 403, and 200.

End of initial candidate answer. This candidate was generated for this worksheet's
AI audit. It is not a claim that a student wrote or independently verified it.
