/* Microsoft Reference Implementation for TPM 2.0
 *
 *  The copyright in this software is being made available under the BSD License,
 *  included below. This software may be subject to other third party and
 *  contributor rights, including patent rights, and no such rights are granted
 *  under this license.
 *
 *  Copyright (c) Microsoft Corporation
 *
 *  All rights reserved.
 *
 *  BSD License
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this list
 *  of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ""AS IS""
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include<stdio.h>
#include "Tpm.h"
#include "CreatePrimary_fp.h"

#if CC_CreatePrimary  // Conditional expansion of this file

/*(See part 3 specification)
// Creates a primary or temporary object from a primary seed.
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES       sensitiveDataOrigin is CLEAR when sensitive.data is an
//                              Empty Buffer 'fixedTPM', 'fixedParent', or
//                              'encryptedDuplication' attributes are inconsistent
//                              between themselves or with those of the parent object;
//                              inconsistent 'restricted', 'decrypt' and 'sign'
//                              attributes
//                              attempt to inject sensitive data for an asymmetric
//                              key;
//      TPM_RC_KDF              incorrect KDF specified for decrypting keyed hash
//                              object
//      TPM_RC_KEY              a provided symmetric key value is not allowed
//      TPM_RC_OBJECT_MEMORY    there is no free slot for the object
//      TPM_RC_SCHEME           inconsistent attributes 'decrypt', 'sign',
//                              'restricted' and key's scheme ID; or hash algorithm is
//                              inconsistent with the scheme ID for keyed hash object
//      TPM_RC_SIZE             size of public authorization policy or sensitive
//                              authorization value does not match digest size of the
//                              name algorithm; or sensitive data size for the keyed
//                              hash object is larger than is allowed for the scheme
//      TPM_RC_SYMMETRIC        a storage key with no symmetric algorithm specified;
//                              or non-storage key with symmetric algorithm different
//                              from TPM_ALG_NULL
//      TPM_RC_TYPE             unknown object type


TPM_RC
TPM2_CreatePrimary(CreatePrimary_In*  in,  // IN: input parameter list
                   CreatePrimary_Out* out  // OUT: output parameter list
)
{
    TPM_RC       result = TPM_RC_SUCCESS;
    TPMT_PUBLIC* publicArea;
    DRBG_STATE   rand;
    OBJECT*      newObject;
    TPM2B_NAME   name;

//GO THROUGH ALL THE BUFFERS AND ADD IN THE LENGTH OF THE BUFFER
    printf("This is the publicArea information-----------------------------------\n");
    printf("This is the authPolicy b buffer: %x\n",publicArea->authPolicy.b.buffer);
    printf("This is the authPolicy b buffer size: %d\n",publicArea->authPolicy.b.size);
    printf("This is the authPolicy t buffer: %x\n",publicArea->authPolicy.t.buffer);
    printf("This is the authPolicy t size: %d\n",publicArea->authPolicy.t.size);
    printf("This is the nameAlg: %s \n",publicArea->nameAlg);
    // printf("\n",publicArea->objectAttributes);
    // printf("\n",publicArea->parameters.asymDetail.scheme.details.anySig.hashAlg);
    // printf("\n",publicArea->parameters.asymDetail.scheme.details.ecdaa.count);
    // printf("\n",publicArea->parameters.asymDetail.scheme.details.ecdaa.hashAlg);
    // printf("\n",publicArea->parameters.asymDetail.scheme.details.ecdh.hashAlg);
    // printf("\n",publicArea->parameters.asymDetail.scheme.details.ecdsa.hashAlg);
    // printf("\n",publicArea->parameters.asymDetail.scheme.details.ecschnorr.hashAlg);
    // printf("\n",publicArea->parameters.asymDetail.scheme.details.oaep.hashAlg);
    // printf("\n",publicArea->parameters.asymDetail.scheme.details.rsaes);
    // printf("\n",publicArea->parameters.asymDetail.scheme.details.rsapss.hashAlg);
    // printf("\n",publicArea->parameters.asymDetail.scheme.details.rsassa.hashAlg);
    printf("This is the unique derevie context b buffer: %x\n",publicArea->unique.derive.context.b.buffer);
    printf("This is the unique derevie context b size: %d\n",publicArea->unique.derive.context.b.size);
    printf("This is the unique derive context t buffer: %x\n",publicArea->unique.derive.context.t.buffer);
    printf("This is the unique derive context t size: %d\n",publicArea->unique.derive.context.t.size);
    printf("This is the unique derive label b buffer: %x\n",publicArea->unique.derive.label.b.buffer);
    printf("This is the unique derive label b size: %d\n",publicArea->unique.derive.label.b.size);
    printf("This is the unique derive label t buffer: %x\n",publicArea->unique.derive.label.t.buffer);
    printf("This is the unique derive label t size: %d\n",publicArea->unique.derive.label.t.size);
    printf("This is the unique ecc x b buffer: %x\n",publicArea->unique.ecc.x.b.buffer);
    printf("This is the unique ecc x b size: %d\n",publicArea->unique.ecc.x.b.size);
    printf("This is the unique ecc x t buffer: %x\n",publicArea->unique.ecc.x.t.buffer);
    printf("This is the unique ecc x t size: %d\n",publicArea->unique.ecc.x.t.size);
    printf("This is the unique ecc y b buffer: %x\n",publicArea->unique.ecc.y.b.buffer);
    printf("This is the unique ecc y b size: %d\n",publicArea->unique.ecc.y.b.size);
    printf("This is the unique ecc y t buffer: %x\n",publicArea->unique.ecc.y.t.buffer);
    printf("This is the unique ecc y t size: %d\n",publicArea->unique.ecc.y.t.size);
    printf("This is the keyhash b buffer: %x\n",publicArea->unique.keyedHash.b.buffer);
    printf("This is the keyhash b size: %d\n",publicArea->unique.keyedHash.b.size);
    printf("This is the keyhash t buffer: %x\n",publicArea->unique.keyedHash.t.buffer);
    printf("This is the keyhash t size: %d\n",publicArea->unique.keyedHash.t.size);
    printf("This is the rsa b buffer: %x\n",publicArea->unique.rsa.b.buffer);
    printf("This is the rsa b size: %d\n",publicArea->unique.rsa.b.size);
    printf("This is the rsa t buffer: %x\n",publicArea->unique.rsa.t.buffer);
    printf("This is the rsa t size: %d\n",publicArea->unique.rsa.t.size);
    printf("This is the sym b buffer: %x\n",publicArea->unique.sym.b.buffer);
    printf("This is the sym b size: %d\n",publicArea->unique.sym.b.size);
    printf("This is the sym t buffer: %x\n",publicArea->unique.sym.t.buffer);
    printf("This is the sym t size: %d\n",publicArea->unique.sym.t.size);
    printf("This is the area Type\n",publicArea->type);


    printf("This is the RAND member information-----------------------------------\n");
    printf("THis is the last value: %d\n",rand.lastValue);
    printf("This is the magic value: %d\n",rand.magic);
    printf("This is the reseedCOunter: %d\n",rand.reseedCounter);
    printf("This is the seed bytes[48]: %x\n",rand.seed.bytes);
    printf("These are the seed words[6]: %s\n", rand.seed.words);

   printf("This is the newObject member information-----------------------------------\n");
    printf("This is set if the key is a derivation: %d\n",newObject->attributes.derivation);
    printf("This is set if the object belongs to EPS: %d\n",newObject->attributes.epsHierarchy);
    printf("This is set if it is a event sequence object: %d\n",newObject->attributes.eventSeq);
    printf("This is set if object is a platform or or owner evict object: %d\n",newObject->attributes.evict);
    printf("This is set if the object is loaded with TPM2_LoadExternal(): %d\n",newObject->attributes.external);
    printf("This is set if first block of hash data has been received: %d\n",newObject->attributes.firstBlock);
    printf("This is set for a hash sequence object: %d\n",newObject->attributes.hashSeq);
    printf("This is set if an HMAC or MAC sequence: %d\n",newObject->attributes.hmacSeq);
    printf("This is set if they key has the proper attributes to be a parent key: %d\n",newObject->attributes.isParent);
    printf("This is set if the private exponent of a key has been used: %d\n",newObject->attributes.not_used_14);
    printf("This is set if the slot has been occupied: %d\n",newObject->attributes.occupied);
    printf("This is set if the object belongs to pps heiarcy: %d\n",newObject->attributes.ppsHierarchy);
    printf("This is set if it is a primary object: %d\n",newObject->attributes.primary);
    printf("This is set if only the public portion of an object is loaded: %d\n",newObject->attributes.publicOnly);
    printf("This is set if object belongs to SPS hierarchy: %d\n",newObject->attributes.spsHierarchy);
    printf("This is set if it is a stClear Object: %d\n",newObject->attributes.stClear);
    printf("This is set if it is a temporary object: %d\n",newObject->attributes.temporary);
    printf("This is set if the ticket is safe to create for a hash sequence object: %d\n",newObject->attributes.ticketSafe);
    printf("If this object is a evict object: %d\n",newObject->evictHandle);
    printf("This is the name b buffer: %x\n",newObject->name.b.buffer);
    printf("This is the name b size: %d\n",newObject->name.b.size);
    printf("This is the name t name[52]: %x\n",newObject->name.t.name);
    printf("This is the name b size: %d\n",newObject->name.t.size);



    printf("This is the authpolicy b buffer[1]: %x\n",newObject->publicArea.authPolicy.b.buffer);
    printf("This is the authpolicy b size: %d\n",newObject->publicArea.authPolicy.b.size);
    printf("This is the authpolicy t buffer[48]: %x\n",newObject->publicArea.authPolicy.t.buffer);
    printf("This is the authpolicy t size: %d\n",newObject->publicArea.authPolicy.t.size);
    printf("This is the unique derive context b buffer: %x\n",newObject->publicArea.unique.derive.context.b.buffer);
    printf("This is the unique derive context b size: %d\n",newObject->publicArea.unique.derive.context.b.size);
    printf("This is the unique derive context b buffer: %x\\n",newObject->publicArea.unique.derive.context.t.buffer);
    // printf("\n",newObject->publicArea.unique.derive.context.t.size);
    // printf("\n",newObject->publicArea.unique.derive.label.b.buffer);
    // printf("\n",newObject->publicArea.unique.derive.label.b.size);
    // printf("\n",newObject->publicArea.unique.derive.label.t.buffer);
    // printf("\n",newObject->publicArea.unique.derive.label.t.size);
    // printf("\n",newObject->publicArea.unique.derive.label.t.buffer);
    // printf("\n",newObject->publicArea.unique.derive.label.t.size);
    // printf("\n",newObject->publicArea.unique.ecc.x.b.buffer);
    // printf("\n",newObject->publicArea.unique.ecc.x.b.size);
    // printf("\n",newObject->publicArea.unique.ecc.x.t.buffer);
    // printf("\n",newObject->publicArea.unique.ecc.x.t.size);
    // printf("\n",newObject->publicArea.unique.ecc.y.b.buffer);
    // printf("\n",newObject->publicArea.unique.ecc.y.b.size);
    // printf("\n",newObject->publicArea.unique.ecc.y.t.buffer);
    // printf("\n",newObject->publicArea.unique.ecc.y.t.size);
    // printf("\n",newObject->publicArea.unique.keyedHash.b.buffer);
    // printf("\n",newObject->publicArea.unique.keyedHash.b.size);
    // printf("\n",newObject->publicArea.unique.keyedHash.t.buffer);
    // printf("\n",newObject->publicArea.unique.keyedHash.t.size);
    // printf("\n",newObject->publicArea.unique.rsa.b.buffer);
    // printf("\n",newObject->publicArea.unique.rsa.b.size);
    // printf("\n",newObject->publicArea.unique.rsa.t.buffer);
    // printf("\n",newObject->publicArea.unique.rsa.t.size);
    // printf("\n",newObject->publicArea.unique.sym.b.buffer);
    // printf("\n",newObject->publicArea.unique.sym.b.size);
    // printf("\n",newObject->publicArea.unique.sym.t.buffer);
    // printf("\n",newObject->publicArea.unique.sym.t.size);

    // printf("\n",newObject->publicArea.type);
    // printf("\n",newObject->qualifiedName.b.buffer);
    // printf("\n",newObject->qualifiedName.b.size);
    // printf("\n",newObject->qualifiedName.t.name);
    // printf("\n",newObject->qualifiedName.t.size);

    // printf("\n");  
    // printf("\n",newObject->sensitive.authValue.b.buffer);
    // printf("\n",newObject->sensitive.authValue.b.size);
    // printf("\n",newObject->sensitive.authValue.t.buffer);
    // printf("\n",newObject->sensitive.authValue.t.size);

    // printf("\n");  
    // printf("\n",newObject->sensitive.seedValue.b.buffer);
    // printf("\n",newObject->sensitive.seedValue.b.size);
    // printf("\n",newObject->sensitive.seedValue.t.buffer);
    // printf("\n",newObject->sensitive.seedValue.t.size);

    // printf("\n");  
    // printf("\n",newObject->sensitive.sensitive.any.b.buffer);
    // printf("\n",newObject->sensitive.sensitive.any.b.size);
    // printf("\n",newObject->sensitive.sensitive.any.t.buffer);
    // printf("\n",newObject->sensitive.sensitive.any.t.size);

    // printf("\n");  
    // printf("\n",newObject->sensitive.sensitive.bits.b.buffer);
    // printf("\n",newObject->sensitive.sensitive.bits.b.size);
    // printf("\n",newObject->sensitive.sensitive.bits.t.buffer);
    // printf("\n",newObject->sensitive.sensitive.bits.t.size);

    // printf("\n");  
    // printf("\n",newObject->sensitive.sensitive.ecc.b.buffer);
    // printf("\n",newObject->sensitive.sensitive.ecc.b.size);
    // printf("\n",newObject->sensitive.sensitive.ecc.t.buffer);
    // printf("\n",newObject->sensitive.sensitive.ecc.t.size);

    // printf("\n");  
    // printf("\n",newObject->sensitive.sensitive.rsa.b.buffer);
    // printf("\n",newObject->sensitive.sensitive.rsa.b.size);
    // printf("\n",newObject->sensitive.sensitive.rsa.t.buffer);
    // printf("\n",newObject->sensitive.sensitive.rsa.t.size);  

    // printf("\n");  
    // printf("\n",newObject->sensitive.sensitive.sym.b.buffer);
    // printf("\n",newObject->sensitive.sensitive.sym.b.size);
    // printf("\n",newObject->sensitive.sensitive.sym.t.buffer);
    // printf("\n",newObject->sensitive.sensitive.sym.t.size);
    // printf("\n",newObject->sensitive.sensitiveType);
    
    // printf("\n");
    // printf("\n",name.b.buffer);  
    // printf("\n",name.b.size);  
    // printf("\n",name.t.name);  
    // printf("\n",name.t.size);  





    // Input Validation
    // Will need a place to put the result
    newObject = FindEmptyObjectSlot(&out->objectHandle);
    if(newObject == NULL)
        return TPM_RC_OBJECT_MEMORY;
    // Get the address of the public area in the new object
    // (this is just to save typing)
    publicArea  = &newObject->publicArea;

    *publicArea = in->inPublic.publicArea;

    // Check attributes in input public area. CreateChecks() checks the things that
    // are unique to creation and then validates the attributes and values that are
    // common to create and load.
    result = CreateChecks(NULL, publicArea, in->inSensitive.sensitive.data.t.size);
    if(result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result, RC_CreatePrimary_inPublic);

    printf("Passed Create Checks\n");
    // Validate the sensitive area values

    printf("starting adjust size method\n");
    if(!AdjustAuthSize(&in->inSensitive.sensitive.userAuth, publicArea->nameAlg))
        printf("failed Adjust AuthSize method,the input authValue is  larger than the digestSize for hte nameALg\n");
        printf("This returns RC SIZE+ CREATE_PRIMARY INSENSITIVE: %x\n",TPM_RCS_SIZE + RC_CreatePrimary_inSensitive);
        return TPM_RCS_SIZE + RC_CreatePrimary_inSensitive;
    
    
    printf("Passed AdjustAuthSize method\n");
    // Command output
    // Compute the name using out->name as a scratch area (this is not the value
    // that ultimately will be returned, then instantiate the state that will be
    // used as a random number generator during the object creation.
    // The caller does not know the seed values so the actual name does not have
    // to be over the input, it can be over the unmarshaled structure.

    printf("Starting DRGB_Instantiate Seeded method\n");
    result =
        DRBG_InstantiateSeeded(&rand,
                               &HierarchyGetPrimarySeed(in->primaryHandle)->b,
                               PRIMARY_OBJECT_CREATION,
                               (TPM2B*)PublicMarshalAndComputeName(publicArea, &name),
                               &in->inSensitive.sensitive.data.b);

    printf("FInished the DRGB_Instantiate Seeded Method\n");
    printf("here is the result of the Instantiate seed method: %x \n", result);
    if(result == TPM_RC_SUCCESS)
    {
        newObject->attributes.primary = SET;
        if(in->primaryHandle == TPM_RH_ENDORSEMENT)
            newObject->attributes.epsHierarchy = SET;

        printf("We made it to the create primary object part\n");
        // Create the primary object.
        result = CryptCreateObject(
            newObject, &in->inSensitive.sensitive, (RAND_STATE*)&rand);

        printf("this is the result of creating CryptCreatObject: %x\n",result);
    }

    if(result != TPM_RC_SUCCESS)
        return result;
    // Set the publicArea and name from the computed values
    out->outPublic.publicArea = newObject->publicArea;
    out->name                 = newObject->name;

    // Fill in creation data
    FillInCreationData(in->primaryHandle,
                       publicArea->nameAlg,
                       &in->creationPCR,
                       &in->outsideInfo,
                       &out->creationData,
                       &out->creationHash);

    // Compute creation ticket
    TicketComputeCreation(EntityGetHierarchy(in->primaryHandle),
                          &out->name,
                          &out->creationHash,
                          &out->creationTicket);

    // Set the remaining attributes for a loaded object
    ObjectSetLoadedAttributes(newObject, in->primaryHandle);
    return result;
}

#endif  // CC_CreatePrimary