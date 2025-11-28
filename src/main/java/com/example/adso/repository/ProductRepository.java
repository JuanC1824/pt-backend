package com.example.adso.repository;

import com.example.adso.model.Product;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.Collection;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Repository
public class ProductRepository {

    private final Map<Long, Product> products = new ConcurrentHashMap<>();
    private final AtomicLong idCounter = new AtomicLong();

    public Collection<Product> findAll() {
        return products.values();
    }

    public Product save(Product product) {
        if (product.getId() == null) {
            product.setId(idCounter.incrementAndGet());
        }
        products.put(product.getId(), product);
        return product;
    }
}
