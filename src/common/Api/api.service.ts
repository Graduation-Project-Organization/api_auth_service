import { Query } from 'mongoose';
import { Injectable } from '@nestjs/common';

export interface IQuery {
  page?: string;
  sort?: string;
  select?: string;
  limit?: string;
  // keyword?: string;
}

export interface Pagination {
  currentPage?: number;
  previousPage?: number;
  nextPage?: number;
  numOfPages?: number;
  skip?: number;
  limit?: number;
  count?: number;
}

@Injectable()
export class ApiService<T, I extends IQuery> {
  query: Query<T[], T>;
  private queryObj: I;
  public paginationObj: Pagination = {
    previousPage: null,
    nextPage: null,
  };
  private filter(obj = {}) {
    let filter = { ...this.queryObj };
    const fields: ('page' | 'limit' | 'select' | 'sort')[] = [
      // 'keyword',
      'page',
      'limit',
      'select',
      'sort',
    ];
    fields.forEach((field) => {
      delete filter[field];
    });
    let queryStr = JSON.stringify(filter);
    queryStr = queryStr.replace(/lt|gt|lte|gte/gi, (val) => `$${val}`);
    filter = JSON.parse(queryStr);
    this.query = this.query.find({ ...filter, ...obj });
    return this;
  }
  private sort() {
    if (this.queryObj.sort) {
      const sort = this.queryObj.sort.split(',').join(' ');
      this.query = this.query.sort(sort);
    } else {
      this.query = this.query.sort('-createdAt');
    }
    return this;
  }
  // private search(fields?: string[]) {
  //   if (this.queryObj.keyword && fields?.length > 0) {
  //     const obj = { $or: [] };
  //     fields.forEach((field) => {
  //       obj.$or.push({
  //         [field]: { $regex: this.queryObj.keyword, $options: 'i' },
  //       });
  //     });
  //     this.query = this.query.find(obj);
  //   }
  //   return this;
  // }
  private select() {
    if (this.queryObj.select) {
      const select = this.queryObj.select.split(',').join(' ');
      this.query.select(select);
    }
    return this;
  }
  private async pagination() {
    this.paginationObj.count = (
      await this.query.model.find({ ...this.query.getQuery() })
    ).length;
    this.paginationObj.currentPage = this.queryObj.page
      ? parseInt(this.queryObj.page)
      : 1;
    this.paginationObj.limit = this.queryObj.limit
      ? parseInt(this.queryObj.limit)
      : 10;
    this.paginationObj.numOfPages = Math.ceil(
      this.paginationObj.count / this.paginationObj.limit,
    );
    this.paginationObj.skip =
      (this.paginationObj.currentPage - 1) * this.paginationObj.limit;
    if (this.paginationObj.currentPage > 1) {
      this.paginationObj.previousPage = this.paginationObj.currentPage - 1;
    }
    if (
      this.paginationObj.count >
      this.paginationObj.currentPage * this.paginationObj.limit
    ) {
      this.paginationObj.nextPage = this.paginationObj.currentPage + 1;
    }
    this.query = this.query
      .skip(this.paginationObj.skip)
      .limit(this.paginationObj.limit);
    return this;
  }
  getAllDocs(
    query: Query<T[], T>,
    queryObj: I,
    obj = {},
    // fields?: string[],
  ): Promise<{ query: Query<T[], T>; paginationObj: Pagination }> {
    this.query = query;
    this.queryObj = queryObj;
    console.log(this.queryObj);
    return this.filter(obj).sort().select().pagination();
  }
}
