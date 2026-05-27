/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Interface.java to edit this template
 */
package com.blazartech.products.blazarusermanagement.tokenutil;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 *
 * @author scott
 */
public interface PublicPrivateKeyHolder {
    
    public PublicKey getPublicKey();
    public PrivateKey getPrivateKey();
}
