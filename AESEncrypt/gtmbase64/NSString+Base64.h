//
//  NSString+Base64.h
//  FreightManage
//
//  Created by ZhangLiang on 15/10/29.
//  Copyright (c) 2015年 ZhangLiang. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (Base64)

+ (NSString*)encodeBase64String:(NSString *)input;
+ (NSString*)decodeBase64String:(NSString *)input;
+ (NSString*)encodeBase64Data:(NSData *)data;
+ (NSString*)decodeBase64Data:(NSData *)data;

@end
